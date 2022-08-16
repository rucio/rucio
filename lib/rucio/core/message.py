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

import json

from typing import TYPE_CHECKING

from sqlalchemy import or_, delete, update
from sqlalchemy.exc import IntegrityError

from rucio.common.constants import HermesService, MAX_MESSAGE_LENGTH
from rucio.common.config import config_get_list
from rucio.common.exception import InvalidObject, RucioException
from rucio.common.utils import APIEncoder, chunks
from rucio.db.sqla import filter_thread_work
from rucio.db.sqla.models import Message, MessageHistory
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional
    from sqlalchemy.orm import Session

    MessageType = Dict[str, Any]
    MessagesListType = List[MessageType]


@transactional_session
def add_messages(messages: "MessagesListType", session: "Optional[Session]" = None) -> None:
    """
    Add a list of messages to be submitted asynchronously to a message broker.

    For messages with payload bigger than MAX_MESSAGE_LENGTH, payload_nolimit is used instead of payload.
    In the case of nolimit, a placeholder string is written to the NOT NULL payload column.

    :param messages: A list of dictionaries {'event_type': str, 'payload': dict}
    :param session: The database session to use.
    """
    services = []
    for service in config_get_list('hermes', 'services_list', raise_exception=False, default='activemq,email', session=session):
        try:
            HermesService(service.upper())
        except ValueError as err:
            raise RucioException(str(err))
        services.append(service)

    msgs = []
    for message in messages:
        event_type = message['event_type']
        payload = message['payload']
        for service in services:
            msg = {'services': service, 'event_type': event_type}
            try:
                if event_type == 'email' and service != 'email':
                    continue
                if service == 'email' and event_type != 'email':
                    continue
                msg_payload = json.dumps(payload, cls=APIEncoder)
                msg['payload'] = msg_payload
                if len(msg_payload) > MAX_MESSAGE_LENGTH:
                    msg['payload_nolimit'] = msg_payload
                    msg['payload'] = 'nolimit'
                msgs.append(msg)
            except TypeError as err:  # noqa: F841
                raise InvalidObject('Invalid JSON for payload: %(err)s' % locals())
    for messages_chunk in chunks(msgs, 1000):
        session.bulk_insert_mappings(Message, messages_chunk)


@transactional_session
def add_message(event_type: str, payload: dict, session: "Optional[Session]" = None) -> None:
    """
    Add a message to be submitted asynchronously to a message broker.

    In the case of nolimit, a placeholder string is written to the NOT NULL payload column.

    :param event_type: The type of the event as a string, e.g., NEW_DID.
    :param payload: The message payload. Will be persisted as JSON.
    :param session: The database session to use.
    """
    add_messages([{'event_type': event_type, 'payload': payload}], session=session)


@transactional_session
def retrieve_messages(bulk: int = 1000,
                      thread: "Optional[int]" = None,
                      total_threads: "Optional[int]" = None,
                      event_type: "Optional[str]" = None,
                      lock: bool = False,
                      old_mode: bool = True,
                      session: "Optional[Session]" = None) -> "MessagesListType":
    """
    Retrieve up to $bulk messages.

    :param bulk: Number of messages as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param event_type: Return only specified event_type. If None, returns everything.
    :param lock: Select exclusively some rows.
    :param old_mode: If True, doesn't return email if event_type is None.
    :param session: The database session to use.

    :returns messages: List of dictionaries {id, created_at, event_type, payload, services}
    """
    messages = []
    try:
        subquery = session.query(Message.id)
        subquery = filter_thread_work(session=session, query=subquery, total_threads=total_threads, thread_id=thread)
        if event_type:
            subquery = subquery.filter_by(event_type=event_type)
        elif old_mode:
            subquery = subquery.filter(Message.event_type != 'email')

        # Step 1:
        # MySQL does not support limits in nested queries, limit on the outer query instead.
        # This is not as performant, but the best we can get from MySQL.
        # FIXME: SQLAlchemy generates wrong nowait MySQL8 statement for MySQL5
        #        Remove once this is resolved in SQLAlchemy
        if session.bind.dialect.name == 'mysql':
            subquery = subquery.order_by(Message.created_at)
            query = session.query(Message.id,
                                  Message.created_at,
                                  Message.event_type,
                                  Message.payload,
                                  Message.services)\
                           .filter(Message.id.in_(subquery))
        else:
            subquery = subquery.order_by(Message.created_at).limit(bulk)
            query = session.query(Message.id,
                                  Message.created_at,
                                  Message.event_type,
                                  Message.payload,
                                  Message.services)\
                           .filter(Message.id.in_(subquery))\
                           .with_for_update(nowait=True)

        # Step 2:
        # MySQL does not support limits in nested queries, limit on the outer query instead.
        # This is not as performant, but the best we can get from MySQL.
        if session.bind.dialect.name == 'mysql':
            query = query.limit(bulk)

        # Step 3:
        # Assemble message object
        for id_, created_at, event_type, payload, services in query:
            message = {'id': id_,
                       'created_at': created_at,
                       'event_type': event_type,
                       'services': services}

            # Only switch SQL context when necessary
            if payload == 'nolimit':
                nolimit_query = session.query(Message.payload_nolimit).filter(Message.id == id_).one()[0]
                message['payload'] = json.loads(str(nolimit_query))
            else:
                message['payload'] = json.loads(str(payload))

            messages.append(message)

        return messages

    except IntegrityError as e:
        raise RucioException(e.args)


@transactional_session
def delete_messages(messages: "MessagesListType", session: "Optional[Session]" = None) -> None:
    """
    Delete all messages with the given IDs, and archive them to the history.

    :param messages: The messages to delete as a list of dictionaries.
    """
    message_condition = []
    for message in messages:
        message_condition.append(Message.id == message['id'])
        if len(message['payload']) > MAX_MESSAGE_LENGTH:
            message['payload_nolimit'] = message.pop('payload')

    try:
        if message_condition:
            stmt = delete(Message).\
                prefix_with("/*+ index(messages MESSAGES_ID_PK) */", dialect='oracle').\
                where(or_(*message_condition)).\
                execution_options(synchronize_session=False)
            session.execute(stmt)

            session.bulk_insert_mappings(MessageHistory, messages)
    except IntegrityError as e:
        raise RucioException(e.args)


@transactional_session
def truncate_messages(session: "Optional[Session]" = None) -> None:
    """
    Delete all stored messages. This is for internal purposes only.

    :param session: The database session to use.
    """

    try:
        session.query(Message).delete(synchronize_session=False)
    except IntegrityError as e:
        raise RucioException(e.args)


@transactional_session
def update_messages_services(messages: "MessagesListType", services: str, session: "Optional[Session]" = None) -> None:
    """
    Update the services for all messages with the given IDs.

    :param messages: The messages to delete as a list of dictionaries.
    :param services: A coma separated string containing the list of services to report to.
    :param session: The database session to use.
    """
    message_condition = []
    for message in messages:
        message_condition.append(Message.id == message['id'])
        if len(message['payload']) > MAX_MESSAGE_LENGTH:
            message['payload_nolimit'] = message.pop('payload')

    try:
        if message_condition:
            stmt = update(Message).\
                prefix_with("/*+ index(messages MESSAGES_ID_PK) */", dialect='oracle').\
                where(or_(*message_condition)).\
                execution_options(synchronize_session=False).\
                values(services=services)
            session.execute(stmt)

    except IntegrityError as err:
        raise RucioException(err.args)
