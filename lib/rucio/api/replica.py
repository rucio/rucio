# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2016
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from rucio.api import permission
from rucio.db.sqla.constants import BadFilesStatus
from rucio.core import replica
from rucio.common import exception
from rucio.common.schema import validate_schema


def get_bad_replicas_summary(rse_expression=None, from_date=None, to_date=None):
    """
    List the bad file replicas summary. Method used by the rucio-ui.
    :param rse_expression: The RSE expression.
    :param from_date: The start date.
    :param to_date: The end date.
    :param session: The database session in use.
    """
    return replica.get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date)


def list_bad_replicas_status(state=BadFilesStatus.BAD, rse=None, younger_than=None, older_than=None, limit=None, list_pfns=False):
    """
    List the bad file replicas history states. Method used by the rucio-ui.
    :param state: The state of the file (SUSPICIOUS or BAD).
    :param rse: The RSE name.
    :param younger_than: datetime object to select bad replicas younger than this date.
    :param older_than:  datetime object to select bad replicas older than this date.
    :param limit: The maximum number of replicas returned.
    """
    return replica.list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than, older_than=older_than, limit=limit, list_pfns=list_pfns)


def declare_bad_file_replicas(pfns, reason, issuer):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    """
    kwargs = {}
    if not permission.has_permission(issuer=issuer, action='declare_bad_file_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not declare bad replicas' % (issuer))
    return replica.declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=issuer, status=BadFilesStatus.BAD)


def declare_suspicious_file_replicas(pfns, reason, issuer):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    """
    kwargs = {}
    if not permission.has_permission(issuer=issuer, action='declare_suspicious_file_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not declare suspicious replicas' % (issuer))
    return replica.declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=issuer, status=BadFilesStatus.SUSPICIOUS)


def get_did_from_pfns(pfns, rse):
    """
    Get the DIDs associated to a PFN on one given RSE

    :param pfns: The list of PFNs.
    :param rse: The RSE name.
    :returns: A dictionary {pfn: {'scope': scope, 'name': name}}
    """
    return replica.get_did_from_pfns(pfns=pfns, rse=rse)


def list_replicas(dids, schemes=None, unavailable=False, request_id=None,
                  ignore_availability=True, all_states=False, rse_expression=None,
                  client_location=None, domain=None, signature_lifetime=None,
                  resolve_archives=True, resolve_parents=False, issuer=None):
    """
    List file replicas for a list of data identifiers.

    :param dids: The list of data identifiers (DIDs).
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param unavailable: Also include unavailable replicas in the list.
    :param request_id: ID associated with the request for debugging.
    :param all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
    :param rse_expression: The RSE expression to restrict replicas on a set of RSEs.
    :param client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site'}
    :param domain: The network domain for the call, either None, 'wan' or 'lan'. Compatibility fallback: None falls back to 'wan'.
    :param signature_lifetime: If supported, in seconds, restrict the lifetime of the signed PFN.
    :param resolve_archives: When set to True, find archives which contain the replicas.
    :param resolve_parents: When set to True, find all parent datasets which contain the replicas.
    :param issuer: The issuer account.
    """
    validate_schema(name='r_dids', obj=dids)

    # Allow selected authenticated users to retrieve signed URLs.
    # Unauthenticated users, or permission-less users will get the raw URL without the signature.
    sign_urls = False
    if permission.has_permission(issuer=issuer, action='get_signed_url', kwargs={}):
        sign_urls = True

    return replica.list_replicas(dids=dids, schemes=schemes, unavailable=unavailable,
                                 request_id=request_id,
                                 ignore_availability=ignore_availability,
                                 all_states=all_states, rse_expression=rse_expression,
                                 client_location=client_location, domain=domain,
                                 sign_urls=sign_urls, signature_lifetime=signature_lifetime,
                                 resolve_archives=resolve_archives, resolve_parents=resolve_parents)


def add_replicas(rse, files, issuer, ignore_availability=False):
    """
    Bulk add file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param ignore_availability: Ignore the RSE blacklisting.

    :returns: True is successful, False otherwise
    """
    validate_schema(name='dids', obj=files)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='add_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add file replicas on %s' % (issuer, rse))
    if not permission.has_permission(issuer=issuer, action='skip_availability_check', kwargs=kwargs):
        ignore_availability = False
    replica.add_replicas(rse=rse, files=files, account=issuer, ignore_availability=ignore_availability)


def delete_replicas(rse, files, issuer, ignore_availability=False):
    """
    Bulk delete file replicas.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    :param ignore_availability: Ignore the RSE blacklisting.

    :returns: True is successful, False otherwise
    """
    validate_schema(name='r_dids', obj=files)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='delete_replicas', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete file replicas on %s' % (issuer, rse))
    if not permission.has_permission(issuer=issuer, action='skip_availability_check', kwargs=kwargs):
        ignore_availability = False
    replica.delete_replicas(rse=rse, files=files, ignore_availability=ignore_availability)


def update_replicas_states(rse, files, issuer):

    """
    Update File replica information and state.

    :param rse: The RSE name.
    :param files: The list of files.
    :param issuer: The issuer account.
    """
    validate_schema(name='dids', obj=files)

    kwargs = {'rse': rse}
    if not permission.has_permission(issuer=issuer, action='update_replicas_states', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update file replicas state on %s' % (issuer, rse))
    replicas = []
    for file in files:
        rep = file
        rep['rse'] = rse
        replicas.append(rep)
    replica.update_replicas_states(replicas=replicas)


def list_dataset_replicas(scope, name, deep=False):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.

    :returns: A list of dict dataset replicas
    """
    return replica.list_dataset_replicas(scope=scope, name=name, deep=deep)


def list_dataset_replicas_vp(scope, name, deep=False):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.

    :returns: If VP exists a list of dicts of sites, otherwise a list of dicts of dataset replicas

    NOTICE: This is an RnD function and might change or go away at any time.
    """
    return replica.list_dataset_replicas_vp(scope=scope, name=name, deep=deep)


def list_datasets_per_rse(rse, filters=None, limit=None):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param limit: limit number.
    :param session: Database session to use.

    :returns: A list of dict dataset replicas
    """
    return replica.list_datasets_per_rse(rse, filters=filters, limit=limit)


def add_bad_pfns(pfns, issuer, state, reason=None, expires_at=None):
    """
    Add bad PFNs.

    :param pfns: the list of new files.
    :param issuer: The issuer account.
    :param state: One of the possible states : BAD, SUSPICIOUS, TEMPORARY_UNAVAILABLE.
    :param reason: A string describing the reason of the loss.
    :param expires_at: Specify a timeout for the TEMPORARY_UNAVAILABLE replicas. None for BAD files.

    :param session: The database session in use.

    :returns: True is successful.
    """
    kwargs = {'state': state}
    if not permission.has_permission(issuer=issuer, action='add_bad_pfns', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not declare bad PFNs' % (issuer))
    return replica.add_bad_pfns(pfns=pfns, account=issuer, state=state, reason=reason, expires_at=expires_at)


def get_suspicious_files(rse_expression, younger_than=None, nattempts=None):
    """
    List the list of suspicious files on a list of RSEs
    :param rse_expression: The RSE expression where the suspicious files are located
    :param younger_than: datetime object to select the suspicious replicas younger than this date.
    :param nattempts: The number of time the replicas have been declared suspicious
    """
    return replica.get_suspicious_files(rse_expression=rse_expression, younger_than=younger_than, nattempts=nattempts)


def set_tombstone(rse, scope, name, issuer):
    """
    Sets a tombstone on one replica.

    :param rse: name of the RSE.
    :param scope: scope of the replica DID.
    :param name: name of the replica DID.
    :param issuer: The issuer account
    """
    if not permission.has_permission(issuer=issuer, action='set_tombstone', kwargs={}):
        raise exception.AccessDenied('Account %s can not set tombstones' % (issuer))
    replica.set_tombstone(rse, scope, name)
