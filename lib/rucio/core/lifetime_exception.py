# -*- coding: utf-8 -*-
# Copyright 2017-2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017-2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

from __future__ import division

from re import match
from datetime import datetime, timedelta
from six import string_types

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.exception import RucioException, LifetimeExceptionDuplicate, LifetimeExceptionNotFound, UnsupportedOperation
from rucio.common.utils import generate_uuid, str_to_date
import rucio.common.policy
from rucio.core.config import get
from rucio.core.message import add_message
from rucio.core.rse import list_rse_attributes

from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, LifetimeExceptionsState
from rucio.db.sqla.session import transactional_session, stream_session, read_session


@stream_session
def list_exceptions(exception_id, states, session=None):
    """
    List exceptions to Lifetime Model.

    :param exception_id: The id of the exception
    :param states:       The states to filter
    :param session:      The database session in use.
    """

    state_clause = []
    if states:
        state_clause = [models.LifetimeExceptions.state == state for state in states]

    query = session.query(models.LifetimeExceptions)
    if state_clause != []:
        query = query.filter(or_(*state_clause))
    if exception_id:
        query = query.filter_by(id=exception_id)

    for exception in query.yield_per(5):
        yield {'id': exception.id, 'scope': exception.scope, 'name': exception.name,
               'did_type': exception.did_type, 'account': exception.account,
               'pattern': exception.pattern, 'comments': exception.comments,
               'state': exception.state, 'created_at': exception.created_at,
               'expires_at': exception.expires_at}


@transactional_session
def add_exception(dids, account, pattern, comments, expires_at, session=None):
    """
    Add exceptions to Lifetime Model.

    :param dids:        The list of dids
    :param account:     The account of the requester.
    :param pattern:     The account.
    :param comments:    The comments associated to the exception.
    :param expires_at:  The expiration date of the exception.
    :param session:     The database session in use.

    returns:            The id of the exception.
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
    if volume:
        text += 'The estimated physical volume is %s\n' % volume
    if expires_at and isinstance(expires_at, string_types):
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
            if isinstance(did['did_type'], string_types):
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
    approvers_email = get('lifetime_model', 'approvers_email', default=[], session=session)
    if approvers_email:
        approvers_email = approvers_email.split(',')  # pylint: disable=no-member

    add_message(event_type='email',
                payload={'body': text, 'to': approvers_email,
                         'subject': '[RUCIO] Request to approve lifetime exception %s' % str(exception_id)},
                session=session)
    return exception_id


@transactional_session
def update_exception(exception_id, state, session=None):
    """
    Update exceptions state to Lifetime Model.

    :param exception_id:   The id of the exception
    :param state:          The states to filter
    :param session:        The database session in use.
    """
    query = session.query(models.LifetimeExceptions).filter_by(id=exception_id)
    try:
        query.first()
    except NoResultFound:
        raise LifetimeExceptionNotFound

    if state in [LifetimeExceptionsState.APPROVED, LifetimeExceptionsState.REJECTED]:
        query.update({'state': state, 'updated_at': datetime.utcnow()}, synchronize_session=False)
    else:
        raise UnsupportedOperation


@read_session
def define_eol(scope, name, rses, session=None):
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
        did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == scope,
                                                          models.DataIdentifier.name == name).one()
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
