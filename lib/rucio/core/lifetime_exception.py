'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2016-2017
'''

from re import match
from datetime import datetime

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.exception import ConfigNotFound, RucioException, LifetimeExceptionDuplicate, LifetimeExceptionNotFound, UnsupportedOperation
from rucio.common.utils import generate_uuid, str_to_date
from rucio.core.config import get
from rucio.core.message import add_message

from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, LifetimeExceptionsState
from rucio.db.sqla.session import transactional_session, stream_session


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

    query = session.query(models.LifetimeExceptions.id,
                          models.LifetimeExceptions.scope, models.LifetimeExceptions.name,
                          models.LifetimeExceptions.did_type,
                          models.LifetimeExceptions.account,
                          models.LifetimeExceptions.pattern,
                          models.LifetimeExceptions.comments,
                          models.LifetimeExceptions.state,
                          models.LifetimeExceptions.expires_at)
    if state_clause != []:
        query = query.filter(or_(*state_clause))
    if exception_id:
        query = query.filter(id=exception_id)

    for exception in query.yield_per(5):
        yield {'id': exception.id, 'scope': exception.scope, 'name': exception.name,
               'did_type': exception.did_type, 'account': exception.account,
               'pattern': exception.pattern, 'comments': exception.comments,
               'state': exception.state, 'expires_at': exception.expires_at}


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
    if comments.find('||||') > -1:
        reason, volume = comments.split('||||')
    text += 'The reason for the extension is "%s"\n' % reason
    text += 'It represents %s datasets\n' % len(dids)
    if volume:
        text += 'The estimated physical volume is %s\n' % volume
    if expires_at and (isinstance(expires_at, str) or isinstance(expires_at, unicode)):
        expires_at = str_to_date(expires_at)
        text += 'The lifetime exception should expires on %s\n' % str(expires_at)
    text += 'Link to approve or reject this request can be found at the end of the mail\n'
    text += '\n'
    text += 'DIDTYPE SCOPE NAME\n'
    text += '\n'
    truncated_message = False
    for did in dids:
        did_type = None
        if 'did_type' in did:
            if isinstance(did['did_type'], str) or isinstance(did['did_type'], unicode):
                did_type = DIDType.from_sym(did['did_type'])
            else:
                did_type = did['did_type']
        if expires_at and (isinstance(expires_at, str) or isinstance(expires_at, unicode)):
            expires_at = str_to_date(expires_at)
        new_exception = models.LifetimeExceptions(id=exception_id, scope=did['scope'], name=did['name'], did_type=did_type,
                                                  account=account, pattern=pattern, comments=reason, state=LifetimeExceptionsState.WAITING, expires_at=expires_at)
        if len(text) < 3500:
            text += '%s %s %s\n' % (str(did_type), did['scope'], did['name'])
        else:
            truncated_message = True
        try:
            new_exception.save(session=session, flush=False)
        except IntegrityError as error:
            if match('.*ORA-00001.*', str(error.args[0]))\
               or match('.*IntegrityError.*UNIQUE constraint failed.*', str(error.args[0]))\
               or match('.*1062.*Duplicate entry.*for key.*', str(error.args[0]))\
               or match('.*sqlite3.IntegrityError.*are not unique.*', error.args[0]):
                raise LifetimeExceptionDuplicate()
            raise RucioException(error.args[0])
    if truncated_message:
        text += '...\n'
        text += 'List too long. Truncated\n'
    text += '\n'
    text += 'Approve:   https://rucio-ui.cern.ch/lifetime_exception?id=%s&action=approve\n' % str(exception_id)
    text += 'Deny:      https://rucio-ui.cern.ch/lifetime_exception?id=%s&action=deny\n' % str(exception_id)
    approvers_email = []
    try:
        approvers_email = get('lifetime_model', 'approvers_email', session=session)
        approvers_email.split(',')  # pylint: disable=no-member
    except ConfigNotFound:
        approvers_email = []
    add_message(event_type='email',
                payload={'body': text,
                         'to': approvers_email,
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
        query.one()
    except NoResultFound:
        raise LifetimeExceptionNotFound

    if state in [LifetimeExceptionsState.APPROVED, LifetimeExceptionsState.REJECTED]:
        query.update({'state': state, 'updated_at': datetime.utcnow()}, synchronize_session=False)
    else:
        raise UnsupportedOperation
