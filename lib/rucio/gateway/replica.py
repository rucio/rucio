# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
from typing import TYPE_CHECKING, Any, Literal, Optional, Union, cast

from rucio.common import exception
from rucio.common.constants import SuspiciousAvailability
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount, InternalScope, IPDict
from rucio.common.utils import gateway_update_return_dict, invert_dict
from rucio.core import replica
from rucio.core.rse import get_rse_id, get_rse_name
from rucio.db.sqla.constants import BadFilesStatus, DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


def get_bad_replicas_summary(
        rse_expression: Optional[str] = None,
        from_date: Optional[datetime.datetime] = None,
        to_date: Optional[datetime.date] = None,
        vo: str = 'def'
) -> list[dict[str, Any]]:
    """
    List the bad file replicas summary. Method used by the rucio-ui.
    :param rse_expression: The RSE expression.
    :param from_date: The start date.
    :param to_date: The end date.
    :param vo: the VO to act on.
    """
    with db_session(DatabaseOperationType.READ) as session:
        replicas = replica.get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date, filter_={'vo': vo}, session=session)
        return [gateway_update_return_dict(r, session=session) for r in replicas]


def list_bad_replicas_status(
        state: Optional[BadFilesStatus] = BadFilesStatus.BAD,
        rse: Optional[str] = None,
        younger_than: Optional[datetime.datetime] = None,
        older_than: Optional[datetime.datetime] = None,
        limit: Optional[int] = None,
        list_pfns: bool = False,
        vo: str = 'def'):
    """
    List the bad file replicas history states. Method used by the rucio-ui.
    :param state: The state of the file (SUSPICIOUS or BAD).
    :param rse: The RSE name.
    :param younger_than: datetime object to select bad replicas younger than this date.
    :param older_than:  datetime object to select bad replicas older than this date.
    :param limit: The maximum number of replicas returned.
    :param vo: The VO to act on.
    """
    rse_id = None

    with db_session(DatabaseOperationType.READ) as session:
        if rse is not None:
            rse_id = get_rse_id(rse=rse, vo=vo, session=session)

        replicas = replica.list_bad_replicas_status(state=state, rse_id=rse_id, younger_than=younger_than,
                                                    older_than=older_than, limit=limit, list_pfns=list_pfns, vo=vo, session=session)
        return [gateway_update_return_dict(r, session=session) for r in replicas]


def declare_bad_file_replicas(
        replicas: Union[list[str], list[dict[str, Any]]],
        reason: str,
        issuer: str,
        vo: str = 'def',
        force: bool = False
) -> dict[str, Any]:
    """
    Declare a list of bad replicas.

    :param replicas: Either a list of PFNs (string) or a list of replicas {'scope': <scope>, 'name': <name>, 'rse_id': <rse_id> or "rse": <rse_name>}.
            If both rse_id and rse are present, rse will be ignored.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param force: boolean, ignore existing replica status in the bad_replicas table. Default: False
    :returns: Dictionary {rse_name -> [list of replicas failed to declare]}
    """

    if not replicas:
        return {}

    as_pfns = isinstance(replicas[0], str)

    # make sure all elements are either strings or dicts, without mixing
    if any(isinstance(r, str) != as_pfns for r in replicas):
        raise exception.InvalidType('The replicas must be specified either as a list of PFNs (strings) or list of dicts')

    rse_map = {}                # RSE name -> RSE id

    replicas_lst = replicas
    rse_ids_to_check = set()        # to check for permission to declare bad replicas

    with db_session(DatabaseOperationType.WRITE) as session:
        if as_pfns:
            scheme, rses_for_replicas, unknowns = replica.get_pfn_to_rse(replicas, vo=vo, session=session)
            if unknowns:
                raise exception.ReplicaNotFound("Not all replicas found")
            rse_ids_to_check = set(rses_for_replicas.keys())
        else:
            # replicas is a list[dict] in this path,
            # but the static code analyzer does not see it due to as_pfns logic above,
            # so cast is used instead
            replicas = cast("list[dict[str, Any]]", replicas)
            replicas_lst = []
            for r in replicas:
                if "name" not in r or "scope" not in r or ("rse" not in r and "rse_id" not in r):
                    raise exception.InvalidType('The replica dictionary must include scope and either rse (name) or rse_id')
                scope = InternalScope(r['scope'], vo=vo)
                rse_id = r.get("rse_id") or rse_map.get(r['rse'])
                if rse_id is None:
                    rse = r["rse"]
                    rse_map[rse] = rse_id = get_rse_id(rse=rse, vo=vo, session=session)
                replicas_lst.append({
                    "rse_id": rse_id,
                    "scope": scope,
                    "name": r["name"]
                })
                rse_ids_to_check.add(rse_id)

        rse_id_to_name = invert_dict(rse_map)   # RSE id -> RSE name

        for rse_id in rse_ids_to_check:
            auth_result = permission.has_permission(issuer=issuer, vo=vo, action='declare_bad_file_replicas',
                                                    kwargs={"rse_id": rse_id},
                                                    session=session)
            if not auth_result.allowed:
                raise exception.AccessDenied('Account %s can not declare bad replicas in RSE %s. %s' %
                                             (issuer, rse_id_to_name.get(rse_id, rse_id), auth_result.message))

        undeclared = replica.declare_bad_file_replicas(replicas_lst, reason=reason,
                                                       issuer=InternalAccount(issuer, vo=vo),
                                                       status=BadFilesStatus.BAD,
                                                       force=force, session=session)
        out = {}
        for rse_id, ulist in undeclared.items():
            if ulist:
                rse_name = None
                if rse_id == 'unknown':
                    rse_name = 'unknown'
                elif rse_id in rse_id_to_name:
                    rse_name = rse_id_to_name[rse_id]
                else:
                    try:
                        rse_name = get_rse_name(rse_id=rse_id, session=session)
                    except (ValueError, exception.RSENotFound):
                        rse_name = str(rse_id)
                if rse_name:
                    out[rse_name] = out.get(rse_name, []) + ulist
        return out


def declare_suspicious_file_replicas(
        pfns: list[Union[str, dict[str, Any]]],
        reason: str,
        issuer: str,
        vo: str = 'def'
) -> dict[str, list[str]]:
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='declare_suspicious_file_replicas', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not declare suspicious replicas. %s' % (issuer, auth_result.message))

        issuer_account = InternalAccount(issuer, vo=vo)

        replicas = replica.declare_bad_file_replicas(pfns, reason=reason, issuer=issuer_account, status=BadFilesStatus.SUSPICIOUS, session=session)

        for k in list(replicas):
            try:
                rse = get_rse_name(rse_id=k, session=session)
                replicas[rse] = replicas.pop(k)
            except exception.RSENotFound:
                pass

    return replicas


def get_did_from_pfns(
        pfns: "Iterable[str]",
        rse: str,
        vo: str = 'def'
) -> 'Iterator[dict[str, dict[str, Any]]]':
    """
    Get the DIDs associated to a PFN on one given RSE

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    :param vo: The VO to act on.
    :returns: A dictionary {pfn: {'scope': scope, 'name': name}}
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)
        replicas = replica.get_did_from_pfns(pfns=pfns, rse_id=rse_id, vo=vo, session=session)

        for r in replicas:
            for k in r.keys():
                r[k]['scope'] = r[k]['scope'].external
            yield r


def list_replicas(
        dids: "Iterable[dict[str, Any]]",
        schemes: Optional[list[str]] = None,
        unavailable: bool = False,
        request_id: Optional[str] = None,
        ignore_availability: bool = True,
        all_states: bool = False,
        rse_expression: Optional[str] = None,
        client_location: Optional[IPDict] = None,
        domain: Optional[str] = None,
        signature_lifetime: Optional[int] = None,
        resolve_archives: bool = True,
        resolve_parents: bool = False,
        nrandom: Optional[int] = None,
        updated_after: Optional[datetime.datetime] = None,
        issuer: Optional[str] = None,
        vo: str = 'def'
) -> 'Iterator[dict[str, Any]]':
    """
    List file replicas for a list of data identifiers.

    :param dids: The list of data identifiers (DIDs).
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param unavailable: (deprecated) Also include unavailable replicas in the list.
    :param request_id: ID associated with the request for debugging.
    :param all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
    :param rse_expression: The RSE expression to restrict replicas on a set of RSEs.
    :param client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    :param domain: The network domain for the call, either None, 'wan' or 'lan'. Compatibility fallback: None falls back to 'wan'.
    :param signature_lifetime: If supported, in seconds, restrict the lifetime of the signed PFN.
    :param resolve_archives: When set to True, find archives which contain the replicas.
    :param resolve_parents: When set to True, find all parent datasets which contain the replicas.
    :param updated_after: datetime object (UTC time), only return replicas updated after this time
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    validate_schema(name='r_dids', obj=dids, vo=vo)

    # Allow selected authenticated users to retrieve signed URLs.
    # Unauthenticated users, or permission-less users will get the raw URL without the signature.
    sign_urls = False

    with db_session(DatabaseOperationType.READ) as session:
        if permission.has_permission(issuer=issuer, vo=vo, action='get_signed_url', kwargs={}, session=session):
            sign_urls = True

        for d in dids:
            d['scope'] = InternalScope(d['scope'], vo=vo)

        replicas = replica.list_replicas(dids=dids, schemes=schemes, unavailable=unavailable,
                                         request_id=request_id,
                                         ignore_availability=ignore_availability,
                                         all_states=all_states, rse_expression=rse_expression,
                                         client_location=client_location, domain=domain,
                                         sign_urls=sign_urls, signature_lifetime=signature_lifetime,
                                         resolve_archives=resolve_archives, resolve_parents=resolve_parents,
                                         nrandom=nrandom, updated_after=updated_after, by_rse_name=True, session=session)

        for rep in replicas:
            rep['scope'] = rep['scope'].external
            if 'parents' in rep:
                new_parents = []
                for p in rep['parents']:
                    scope, name = p.split(':')
                    scope = InternalScope(scope, from_external=False).external
                    new_parents.append('{}:{}'.format(scope, name))
                rep['parents'] = new_parents

            yield rep


def add_replicas(
        rse: str,
        files: "Iterable[dict[str, Any]]",
        issuer: str,
        ignore_availability: bool = False,
        vo: str = 'def'
) -> None:
    """
    Bulk add file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param ignore_availability: Ignore blocked RSEs.
    :param vo: The VO to act on.
    """
    for v_file in files:
        v_file.update({"type": "FILE"})  # Make sure DIDs are identified as files for checking
    validate_schema(name='dids', obj=files, vo=vo)

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_replicas', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not add file replicas on %s. %s' % (issuer, rse, auth_result.message))
        if not permission.has_permission(issuer=issuer, vo=vo, action='skip_availability_check', kwargs=kwargs, session=session):
            ignore_availability = False

        issuer_account = InternalAccount(issuer, vo=vo)
        for f in files:
            f['scope'] = InternalScope(f['scope'], vo=vo)
            if 'account' in f:
                f['account'] = InternalAccount(f['account'], vo=vo)

        replica.add_replicas(rse_id=rse_id, files=files, account=issuer_account, ignore_availability=ignore_availability, session=session)


def delete_replicas(
        rse: str,
        files: "Iterable[dict[str, Any]]",
        issuer: str,
        ignore_availability: bool = False,
        vo: str = 'def'
) -> None:
    """
    Bulk delete file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param ignore_availability: Ignore blocked RSEs.
    :param vo: The VO to act on.
    """
    validate_schema(name='r_dids', obj=files, vo=vo)

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='delete_replicas', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not delete file replicas on %s. %s' % (issuer, rse, auth_result.message))
        if not permission.has_permission(issuer=issuer, vo=vo, action='skip_availability_check', kwargs=kwargs, session=session):
            ignore_availability = False

        for f in files:
            f['scope'] = InternalScope(f['scope'], vo=vo)

        replica.delete_replicas(rse_id=rse_id, files=files, ignore_availability=ignore_availability, session=session)


def update_replicas_states(
        rse: str,
        files: "Iterable[dict[str, Any]]",
        issuer: str,
        vo: str = 'def'
) -> None:
    """
    Update File replica information and state.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    for v_file in files:
        v_file.update({"type": "FILE"})  # Make sure DIDs are identified as files for checking
    validate_schema(name='dids', obj=files, vo=vo)

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'rse': rse, 'rse_id': rse_id}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='update_replicas_states', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update file replicas state on %s. %s' % (issuer, rse, auth_result.message))
        replicas = []
        for file in files:
            rep = file
            rep['rse_id'] = rse_id
            rep['scope'] = InternalScope(rep['scope'], vo=vo)
            replicas.append(rep)
        replica.update_replicas_states(replicas=replicas, session=session)


def list_dataset_replicas(
        scope: str,
        name: str,
        deep: bool = False,
        vo: str = 'def'
) -> "Iterator[dict[str, Any]]":
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.
    :param vo: The VO to act on.

    :returns: A list of dict dataset replicas
    """

    internal_scope = InternalScope(scope, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        replicas = replica.list_dataset_replicas(scope=internal_scope, name=name, deep=deep, session=session)

        for r in replicas:
            r['scope'] = r['scope'].external
            yield r


def list_dataset_replicas_bulk(
        dids: 'Iterable[dict[str, Any]]',
        vo: str = 'def'
) -> 'Iterator[dict[str, Any]]':
    """
    :param dids: The list of did dictionaries with scope and name.
    :param vo: The VO to act on.

    :returns: A list of dict dataset replicas
    """

    validate_schema(name='r_dids', obj=dids, vo=vo)
    names_by_scope = dict()
    for d in dids:
        if d['scope'] in names_by_scope:
            names_by_scope[d['scope']].append(d['name'])
        else:
            names_by_scope[d['scope']] = [d['name'], ]

    names_by_intscope = dict()
    for scope in names_by_scope:
        internal_scope = InternalScope(scope, vo=vo)
        names_by_intscope[internal_scope] = names_by_scope[scope]

    with db_session(DatabaseOperationType.READ) as session:
        replicas = replica.list_dataset_replicas_bulk(names_by_intscope, session=session)

        for r in replicas:
            yield gateway_update_return_dict(r, session=session)


def list_dataset_replicas_vp(
        scope: str,
        name: str,
        deep: bool = False,
        vo: str = 'def'
) -> 'Iterator[dict[str, Any]]':
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.
    :param vo: The vo to act on.

    :returns: If VP exists a list of dicts of sites, otherwise nothing

    NOTICE: This is an RnD function and might change or go away at any time.
    """

    internal_scope = InternalScope(scope, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        for r in replica.list_dataset_replicas_vp(scope=internal_scope, name=name, deep=deep, session=session):
            yield gateway_update_return_dict(r, session=session)


def list_datasets_per_rse(rse: str, filters: Optional[dict[str, Any]] = None, limit: Optional[int] = None, vo: str = 'def') -> 'Iterator[dict[str, Any]]':
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param limit: limit number.
    :param vo: The VO to act on.

    :returns: A list of dict dataset replicas
    """

    filters = filters or {}

    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)
        if 'scope' in filters:
            filters['scope'] = InternalScope(filters['scope'], vo=vo)
        for r in replica.list_datasets_per_rse(rse_id, filters=filters, limit=limit, session=session):
            yield gateway_update_return_dict(r, session=session)


def add_bad_pfns(
        pfns: "Iterable[str]",
        issuer: str,
        state: BadFilesStatus,
        reason: Optional[str] = None,
        expires_at: Optional[datetime.datetime] = None,
        vo: str = 'def'
) -> Literal[True]:
    """
    Add bad PFNs.

    :param pfns: the list of new files.
    :param issuer: The issuer account.
    :param state: One of the possible states : BAD, SUSPICIOUS, TEMPORARY_UNAVAILABLE.
    :param reason: A string describing the reason of the loss.
    :param expires_at: Specify a timeout for the TEMPORARY_UNAVAILABLE replicas. None for BAD files.
    :param vo: The VO to act on.

    :returns: True is successful.
    """
    kwargs = {'state': state}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_bad_pfns', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not declare bad PFNs. %s' % (issuer, auth_result.message))

        if expires_at and datetime.datetime.utcnow() <= expires_at and expires_at > datetime.datetime.utcnow() + datetime.timedelta(days=30):
            raise exception.InputValidationError('The given duration of %s days exceeds the maximum duration of 30 days.' % (expires_at - datetime.datetime.utcnow()).days)

        issuer_account = InternalAccount(issuer, vo=vo)

        return replica.add_bad_pfns(pfns=pfns, account=issuer_account, state=state, reason=reason, expires_at=expires_at, session=session)


def add_bad_dids(
        dids: "Iterable[dict[str, Any]]",
        rse: str,
        issuer: str,
        state: BadFilesStatus,
        reason: Optional[str] = None,
        expires_at: Optional[datetime.datetime] = None,
        vo: str = 'def'
) -> list[str]:
    """
    Add bad replica entries for DIDs.

    :param dids: the list of dids with bad replicas at rse.
    :param rse: the rse with the bad replicas.
    :param issuer: The issuer account.
    :param state: One of the possible states : BAD
    :param reason: A string describing the reason of the loss.
    :param expires_at: None
    :param vo: The VO to act on.

    :returns: The list of replicas not declared bad
    """
    kwargs = {'state': state}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_bad_pfns', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not declare bad PFN or DIDs. %s' % (issuer, auth_result.message))

        issuer_account = InternalAccount(issuer, vo=vo)
        rse_id = get_rse_id(rse=rse, session=session)

        return replica.add_bad_dids(dids=dids, rse_id=rse_id, reason=reason, issuer=issuer_account, state=state, session=session)


def get_suspicious_files(
        rse_expression: Optional[str],
        younger_than: Optional[datetime.datetime] = None,
        nattempts: Optional[int] = None,
        vo: str = 'def'
) -> list[dict[str, Any]]:
    """
    List the list of suspicious files on a list of RSEs
    :param rse_expression: The RSE expression where the suspicious files are located
    :param younger_than: datetime object to select the suspicious replicas younger than this date.
    :param nattempts: The number of time the replicas have been declared suspicious
    :param vo: The VO to act on.
    """

    with db_session(DatabaseOperationType.READ) as session:
        replicas = replica.get_suspicious_files(rse_expression=rse_expression, available_elsewhere=SuspiciousAvailability["ALL"].value,
                                                younger_than=younger_than, nattempts=nattempts, filter_={'vo': vo}, session=session)
        return [gateway_update_return_dict(r, session=session) for r in replicas]


def set_tombstone(
        rse: str,
        scope: str,
        name: str,
        issuer: str,
        vo: str = 'def'
) -> None:
    """
    Sets a tombstone on one replica.

    :param rse: name of the RSE.
    :param scope: scope of the replica DID.
    :param name: name of the replica DID.
    :param issuer: The issuer account
    :param vo: The VO to act on.
    """

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = get_rse_id(rse, vo=vo, session=session)

        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='set_tombstone', kwargs={}, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not set tombstones. %s' % (issuer, auth_result.message))

        internal_scope = InternalScope(scope, vo=vo)
        replica.set_tombstone(rse_id, internal_scope, name, session=session)
