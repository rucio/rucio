# Copyright 2014-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2019
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2016
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

import json

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import bindparam, text


from rucio.common.exception import InvalidObject, RucioException
from rucio.db.sqla.models import Message, MessageHistory
from rucio.db.sqla.session import transactional_session


@transactional_session
def add_message(event_type, payload, session=None):
    """
    Add a message to be submitted asynchronously to a message broker.

    In the case of nolimit, a placeholder string is written to the NOT NULL payload column.

    :param event_type: The type of the event as a string, e.g., NEW_DID.
    :param payload: The message payload. Will be persisted as JSON.
    :param session: The database session to use.
    """

    try:
        payload = json.dumps(payload)
    except TypeError as e:
        raise InvalidObject('Invalid JSON for payload: %(e)s' % locals())

    if len(payload) > 4000:
        new_message = Message(event_type=event_type, payload='nolimit', payload_nolimit=payload)
    else:
        new_message = Message(event_type=event_type, payload=payload)

    new_message.save(session=session, flush=False)


@transactional_session
def retrieve_messages(bulk=1000, thread=None, total_threads=None, event_type=None,
                      lock=False, session=None):
    """
    Retrieve up to $bulk messages.

    :param bulk: Number of messages as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param event_type: Return only specified event_type. If None, returns everything except email.
    :param lock: Select exclusively some rows.
    :param session: The database session to use.

    :returns messages: List of dictionaries {id, created_at, event_type, payload}
    """
    messages = []
    try:
        subquery = session.query(Message.id)
        if total_threads and (total_threads - 1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
                subquery = subquery.filter(text('ORA_HASH(id, :total_threads) = :thread_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                subquery = subquery.filter('mod(md5(id), %s) = %s' % (total_threads - 1, thread))
            elif session.bind.dialect.name == 'postgresql':
                subquery = subquery.filter('mod(abs((\'x\'||md5(id::text))::bit(32)::int), %s) = %s' % (total_threads - 1, thread))

        if event_type:
            subquery = subquery.filter_by(event_type=event_type)
        else:
            subquery = subquery.filter(Message.event_type != 'email')

        # Step 1:
        # MySQL does not support limits in nested queries, limit on the outer query instead.
        # This is not as performant, but the best we can get from MySQL.
        if session.bind.dialect.name == 'mysql':
            subquery = subquery.order_by(Message.created_at)
        else:
            subquery = subquery.order_by(Message.created_at).limit(bulk)

        query = session.query(Message.id,
                              Message.created_at,
                              Message.event_type,
                              Message.payload)\
            .filter(Message.id.in_(subquery))\
            .with_for_update(nowait=True)

        # Step 2:
        # MySQL does not support limits in nested queries, limit on the outer query instead.
        # This is not as performant, but the best we can get from MySQL.
        if session.bind.dialect.name == 'mysql':
            query = query.limit(bulk)

        # Step 3:
        # Assemble message object
        for id, created_at, event_type, payload in query:
            message = {'id': id,
                       'created_at': created_at,
                       'event_type': event_type}

            # Only switch SQL context when necessary
            if payload == 'nolimit':
                nolimit_query = session.query(Message.payload_nolimit).filter(Message.id == id).one()[0]
                message['payload'] = json.loads(str(nolimit_query))
            else:
                message['payload'] = json.loads(str(payload))

            messages.append(message)

        return messages

    except IntegrityError as e:
        raise RucioException(e.args)


@transactional_session
def delete_messages(messages, session=None):
    """
    Delete all messages with the given IDs, and archive them to the history.

    :param messages: The messages to delete as a list of dictionaries.
    """
    message_condition = []
    for message in messages:
        message_condition.append(Message.id == message['id'])

    try:
        if message_condition:
            session.query(Message).\
                with_hint(Message, "index(messages MESSAGES_ID_PK)", 'oracle').\
                filter(or_(*message_condition)).\
                delete(synchronize_session=False)

            session.bulk_insert_mappings(MessageHistory, messages)
    except IntegrityError as e:
        raise RucioException(e.args)


@transactional_session
def truncate_messages(session=None):
    """
    Delete all stored messages. This is for internal purposes only.

    :param session: The database session to use.
    """

    try:
        session.query(Message).delete(synchronize_session=False)
    except IntegrityError as e:
        raise RucioException(e.args)
