# -*- coding: utf-8 -*-
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

from re import match
from datetime import datetime, timedelta
from configparser import NoSectionError
from typing import TYPE_CHECKING

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.config import config_get
from rucio.common.exception import RucioException, LifetimeExceptionDuplicate, LifetimeExceptionNotFound, UnsupportedOperation, ConfigNotFound
from rucio.common.utils import generate_uuid, str_to_date
import rucio.common.policy
from rucio.core.message import add_message

from rucio.core.rse import list_rse_attributes

from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, LifetimeExceptionsState
from rucio.db.sqla.session import transactional_session, stream_session, read_session

if TYPE_CHECKING:
    from typing import Any, Dict, Iterator, List, Optional, Union
    from rucio.common.types import InternalAccount, InternalScope
    from sqlalchemy.orm import Session


@stream_session
def list_exceptions(
        exception_id: 'Optional[str]',
        states: 'List[LifetimeExceptionsState]',
        session: 'Optional[Session]' = None
) -> 'Iterator[Dict[str, Any]]':
    """
    List exceptions to Lifetime Model.

    :param exception_id: The id of the exception
    :param states:       The states to filter
    :param session:      The database session in use.
    """

    state_clause = []
    if states:
        state_clause = [models.LifetimeExceptions.state == state for state in states]

    query = select(models.LifetimeExceptions)
    if state_clause != []:
        query = query.where(or_(*state_clause))
    if exception_id:
        query = query.filter_by(id=exception_id)

    for exception in session.execute(query).yield_per(5).scalars():
        yield {'id': exception.id, 'scope': exception.scope, 'name': exception.name,
               'did_type': exception.did_type, 'account': exception.account,
               'pattern': exception.pattern, 'comments': exception.comments,
               'state': exception.state, 'created_at': exception.created_at,
               'expires_at': exception.expires_at}


@transactional_session
def add_exception(
        dids: 'List[Dict[str, Any]]',
        account: 'InternalAccount',
        pattern: 'Optional[str]',
        comments: str,
        expires_at: 'Optional[Union[str, datetime]]',
        session: 'Optional[Session]' = None
) -> 'Dict[str, Any]':
    """
    Add exceptions to Lifetime Model.

    :param dids:        The list of dids
    :param account:     The account of the requester.
    :param pattern:     The account.
    :param comments:    The comments associated to the exception.
    :param expires_at:  The expiration date of the exception.
    :param session:     The database session in use.

    returns:            A dictionary with id of the exceptions split by scope, datatype.
    """
    from rucio.core.did import get_metadata_bulk
    result = dict()
    result['exceptions'] = dict()
    try:
        max_extension = config_get('lifetime_model', 'max_extension', default=None, session=session)
        if max_extension:
            if not expires_at:
                expires_at = datetime.utcnow() + timedelta(days=max_extension)
            else:
                if isinstance(expires_at, str):
                    expires_at = str_to_date(expires_at)
                if expires_at > datetime.utcnow() + timedelta(days=max_extension):
                    expires_at = datetime.utcnow() + timedelta(days=max_extension)
    except (ConfigNotFound, ValueError, NoSectionError):
        max_extension = None

    try:
        cutoff_date = config_get('lifetime_model', 'cutoff_date', default=None, session=session)
    except (ConfigNotFound, NoSectionError):
        raise UnsupportedOperation('Cannot submit exception at that date.')
    try:
        cutoff_date = datetime.strptime(cutoff_date, '%Y-%m-%d')
    except ValueError:
        raise UnsupportedOperation('Cannot submit exception at that date.')
    if cutoff_date < datetime.utcnow():
        raise UnsupportedOperation('Cannot submit exception at that date.')

    did_group = dict()
    not_affected = list()
    list_dids = [(did['scope'], did['name']) for did in dids]
    metadata = [meta for meta in get_metadata_bulk(dids=dids, session=session)]
    for did in metadata:
        scope, name, did_type = did['scope'], did['name'], did['did_type']
        if (scope, name) in list_dids:
            list_dids.remove((scope, name))
        datatype = did.get('datatype', '')
        eol_at = did.get('eol_at', None)
        if eol_at and eol_at < cutoff_date:
            if (scope, datatype) not in did_group:
                did_group[(scope, datatype)] = [list(), 0]
            did_group[(scope, datatype)][0].append({'scope': scope, 'name': name, 'did_type': did_type})
            did_group[(scope, datatype)][1] += did['bytes'] or 0
        else:
            not_affected.append((scope, name, did_type))
    for entry in did_group:
        exception_id = __add_exception(did_group[entry][0], account=account, pattern=pattern, comments=comments, expires_at=expires_at, estimated_volume=did_group[entry][1], session=session)
        result['exceptions'][exception_id] = did_group[entry][0]
    result['unknown'] = [{'scope': did[0], 'name': did[1], 'did_type': DIDType.DATASET} for did in list_dids]
    result['not_affected'] = [{'scope': did[0], 'name': did[1], 'did_type': did[2]} for did in not_affected]
    return result


@transactional_session
def __add_exception(
        dids: 'List[Dict[str, Any]]',
        account: 'InternalAccount',
        pattern: 'Optional[str]',
        comments: str,
        expires_at: 'Optional[Union[str, datetime]]',
        estimated_volume: 'Optional[int]' = None,
        session: 'Optional[Session]' = None
) -> str:
    """
    Add exceptions to Lifetime Model.

    :param dids:                   The list of dids
    :param account:                The account of the requester.
    :param pattern:                The pattern of the exception (not used).
    :param comments:               The comments associated to the exception.
    :param expires_at:             The expiration date of the exception.
    :params estimated_volume:      The estimated logical volume of the exception.
    :param session:                The database session in use.

    returns:                       The id of the exception.
    """
    exception_id = generate_uuid()
    text = 'Account %s requested a lifetime extension for a list of DIDs that can be found below\n' % account
    reason = comments
    volume = None
    lifetime = None
    if comments.find('||||') > -1:
        reason, volume = comments.split('||||')
    text += 'The reason for the extension is "%s"\n' % reason
    text += 'It represents %s datasets\n' % len(dids)
    if estimated_volume:
        text += 'The estimated logical volume is %s\n' % estimated_volume
    if volume:
        text += 'The estimated physical volume is %s\n' % volume
    if expires_at and isinstance(expires_at, str):
        lifetime = str_to_date(expires_at)
        text += 'The lifetime exception should expires on %s\n' % str(expires_at)
    elif isinstance(expires_at, datetime):
        lifetime = expires_at
        text += 'The lifetime exception should expires on %s\n' % str(expires_at)
    text += 'Link to approve or reject this request can be found at the end of the mail\n'
    text += '\n'
    text += 'DIDTYPE SCOPE NAME\n'
    text += '\n'
    truncated_message = False
    for did in dids:
        did_type = None
        if 'did_type' in did:
            if isinstance(did['did_type'], str):
                did_type = DIDType[did['did_type']]
            else:
                did_type = did['did_type']
        new_exception = models.LifetimeExceptions(id=exception_id, scope=did['scope'], name=did['name'], did_type=did_type,
                                                  account=account, pattern=pattern, comments=reason, state=LifetimeExceptionsState.WAITING, expires_at=lifetime)
        if len(text) < 3000:
            text += '%s %s %s\n' % (str(did_type), did['scope'], did['name'])
        else:
            truncated_message = True
        try:
            new_exception.save(session=session, flush=False)
        except IntegrityError as error:
            if match('.*ORA-00001.*', str(error.args[0])) \
                    or match('.*IntegrityError.*UNIQUE constraint failed.*', str(error.args[0])) \
                    or match('.*1062.*Duplicate entry.*for key.*', str(error.args[0])) \
                    or match('.*IntegrityError.*columns? .*not unique.*', error.args[0]):
                raise LifetimeExceptionDuplicate()
            raise RucioException(error.args[0])
    if truncated_message:
        text += '...\n'
        text += 'List too long. Truncated\n'
    text += '\n'
    text += 'Approve:   https://rucio-ui.cern.ch/lifetime_exception?id=%s&action=approve\n' % str(exception_id)
    text += 'Deny:      https://rucio-ui.cern.ch/lifetime_exception?id=%s&action=deny\n' % str(exception_id)
    approvers_email = config_get('lifetime_model', 'approvers_email', default=[], session=session)
    if approvers_email:
        approvers_email = approvers_email.split(',')  # pylint: disable=no-member

    add_message(event_type='email',
                payload={'body': text, 'to': approvers_email,
                         'subject': '[RUCIO] Request to approve lifetime exception %s' % str(exception_id)},
                session=session)
    return exception_id


@transactional_session
def update_exception(
        exception_id: str,
        state: LifetimeExceptionsState,
        session: 'Optional[Session]' = None
) -> None:
    """
    Update exceptions state to Lifetime Model.

    :param exception_id:   The id of the exception
    :param state:          The states to filter
    :param session:        The database session in use.
    """
    ALLOWED_STATES = (LifetimeExceptionsState.APPROVED, LifetimeExceptionsState.REJECTED)
    if state not in ALLOWED_STATES:
        raise UnsupportedOperation

    query = update(
        models.LifetimeExceptions
    ).where(
        models.LifetimeExceptions.id == exception_id
    ).values(
        state=state,
        updated_at=datetime.utcnow()
    )

    if session.execute(query).rowcount == 0:
        raise LifetimeExceptionNotFound


@read_session
def define_eol(
        scope: 'InternalScope',
        name: str,
        rses: 'List[Dict[str, Any]]',
        session: 'Optional[Session]' = None
) -> 'Optional[datetime]':
    """
    ATLAS policy for rules on SCRATCHDISK

    :param scope:    Scope of the DID.
    :param name:     Name of the DID.
    :param rses:     List of RSEs.
    :param session:  The database session in use.
    """
    policy = rucio.common.policy.get_policy()
    if policy != 'atlas':
        return None

    # Check if on ATLAS managed space
    if [rse for rse in rses if list_rse_attributes(rse_id=rse['id'], session=session).get('type') in ['LOCALGROUPDISK', 'LOCALGROUPTAPE', 'GROUPDISK', 'GROUPTAPE']]:
        return None
    # Now check the lifetime policy
    try:
        query = select(
            models.DataIdentifier
        ).where(
            models.DataIdentifier.scope == scope,
            models.DataIdentifier.name == name
        )

        did = session.execute(query).scalar_one()
    except NoResultFound:
        return None
    policy_dict = rucio.common.policy.get_lifetime_policy()
    did_type = 'other'
    if scope.external.startswith('mc'):
        did_type = 'mc'
    elif scope.external.startswith('data'):
        did_type = 'data'
    elif scope.external.startswith('valid'):
        did_type = 'valid'
    else:
        did_type = 'other'
    for policy in policy_dict[did_type]:
        if 'exclude' in policy:
            to_exclude = False
            for key in policy['exclude']:
                meta_key = None
                if key not in ['datatype', 'project', ]:
                    if key == 'stream':
                        meta_key = 'stream_name'
                    elif key == 'tags':
                        meta_key = 'version'
                else:
                    meta_key = key
                values = policy['exclude'][key]
                for value in values:
                    value = value.replace('%', '.*')
                    if meta_key and did[meta_key] and value and match(value, did[meta_key]):
                        to_exclude = True
                        break
                if to_exclude:
                    break
            if to_exclude:
                continue
        if 'include' in policy:
            match_policy = True
            for key in policy['include']:
                meta_key = None
                if key not in ['datatype', 'project', ]:
                    if key == 'stream':
                        meta_key = 'stream_name'
                    elif key == 'tags':
                        meta_key = 'version'
                    else:
                        continue
                else:
                    meta_key = key
                values = policy['include'][key]
                to_keep = False
                for value in values:
                    value = value.replace('%', '.*')
                    if meta_key and did[meta_key] and value and match(value, did[meta_key]):
                        to_keep = True
                        break
                match_policy = match_policy and to_keep
                if not to_keep:
                    match_policy = False
                    break
            if match_policy:
                if int(policy['age']) >= 12:
                    years = int(int(policy['age']) / 12)
                    months = int(policy['age']) - years * 12
                    lifetime_value = 365 * years + 30 * months
                else:
                    lifetime_value = int(policy['age']) * 30
                if int(policy['extension']) >= 12:
                    years = int(int(policy['extension']) / 12)
                    months = int(policy['extension']) - years * 12
                    extension = 365 * years + 30 * months
                else:
                    extension = int(policy['extension']) * 30

                default_eol_at = did.created_at + timedelta(days=lifetime_value)
                eol_at = default_eol_at
                if did.accessed_at:
                    eol_at = did.accessed_at + timedelta(days=extension)
                    if eol_at < default_eol_at:
                        eol_at = default_eol_at
                return eol_at
    return None
