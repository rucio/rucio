# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

import json

from sqlalchemy.exc import IntegrityError

from rucio.common.exception import InvalidObject, RucioException
from rucio.db.models import Message
from rucio.db.session import transactional_session


@transactional_session
def add_message(event_type, payload, session=None):
    """
    Add a message to be submitted asynchronously to a message broker.

    :param event_type: The type of the event as a string, e.g., NEW_DID.
    :param payload: The message payload. Will be persisted as JSON.
    :param session: The database session to use.
    """

    try:
        new_message = Message(event_type=event_type, payload=json.dumps(payload))
    except TypeError, e:
        raise InvalidObject('Invalid JSON for payload: %(e)s' % locals())

    new_message.save(session=session, flush=False)


@transactional_session
def retrieve_messages(limit=100, session=None):
    """
    Retrieve up to $limit messages.

    :param limit: Number of messages as an int.
    :param session: The database session to use.

    :returns messages: List of dictionaries {id, created_at, event_type, payload}
    """

    messages = []

    try:
        tmp = session.query(Message).limit(limit).all()
        for t in tmp:
            messages.append({'id': t['id'],
                             'created_at': t['created_at'],
                             'event_type': t['event_type'],
                             'payload': json.loads(str(t['payload']))})
        return messages

    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def delete_messages(ids, session=None):
    """
    Delete all messages with the given IDs.

    :param ids: The message IDs, as a list of strings.
    """

    try:
        for id in ids:
            session.query(Message).filter_by(id=id).delete(synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def truncate_messages(session=None):
    """
    Delete all stored messages. This is for internal purposes only.

    :param session: The database session to use.
    """

    try:
        session.query(Message).delete(synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)
