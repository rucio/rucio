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
import random
import string

import pytest

from rucio.db.sqla.models import Message
from rucio.db.sqla.session import get_session
from rucio.common.constants import MAX_MESSAGE_LENGTH
from rucio.common.exception import InvalidObject, RucioException
from rucio.common.utils import generate_uuid
from rucio.core.message import add_message, add_messages, retrieve_messages, delete_messages, truncate_messages


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('hermes', 'services_list', 'influx,activemq,elastic,email'),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_add_message(core_config_mock, caches_mock):
    """ MESSAGE (CORE): Test valid and invalid message """

    truncate_messages()

    add_message(event_type='NEW_DID', payload={'name': 'name',
                                               'name_Y': 'scope_X',
                                               'type': 'file'})

    with pytest.raises(InvalidObject):
        add_message(event_type='NEW_DID', payload={'name': 'name',
                                                   'name_Y': 'scope_X',
                                                   'type': int})


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('hermes', 'services_list', 'influx,activemq,elastic,email'),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_bulk_insert_and_pop_messages(core_config_mock, caches_mock):
    """ MESSAGE (CORE): Test bulk insert, retrieve and delete messages """

    truncate_messages()
    list_messages = []
    messages = []
    for cnt in range(10):
        messages.append(
            {
                "event_type": generate_uuid()[:10],
                "payload": {"foo": True, "monty": "python", "number": cnt},
            }
        )
    add_messages(messages)

    list_messages = retrieve_messages(40)
    assert len(list_messages) == 30
    to_delete = []
    for message in messages:
        filtered_messages = [msg for msg in list_messages if msg['event_type'] == message['event_type']]
        assert len(filtered_messages) == 3
        services = ['influx', 'activemq', 'elastic']
        for msg in filtered_messages:
            assert isinstance(msg['payload'], dict)
            assert msg['payload']['foo'] is True
            assert msg['payload']['monty'] == 'python'
            assert msg['payload']['number'] in list(range(10))
            assert msg['services'] in services
            services.remove(msg['services'])
            to_delete.append(
                {
                    "id": msg["id"],
                    "created_at": msg["created_at"],
                    "updated_at": msg["created_at"],
                    "payload": str(msg["payload"]),
                    "event_type": msg["event_type"],
                }
            )
    delete_messages(to_delete)

    assert retrieve_messages() == []


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('hermes', 'services_list', 'influx,activemq,elastic,email'),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_large_payload(core_config_mock, caches_mock):
    """ MESSAGE (CORE): Test insert and retrieving of message with large payload """
    truncate_messages()

    long_payload = ''.join(random.choice(string.ascii_letters) for i in range(MAX_MESSAGE_LENGTH + 20))
    dict_long_payload = {"mylong_message": long_payload}
    event_type = generate_uuid()[:10]
    add_message(event_type=event_type, payload=dict_long_payload)

    session = get_session()
    msg = session.query(Message.id,   # pylint: disable=no-member
                        Message.created_at,
                        Message.event_type,
                        Message.payload,
                        Message.payload_nolimit,
                        Message.services)\
        .filter_by(event_type=event_type)\
        .first()
    assert msg.payload == 'nolimit'
    assert msg.payload_nolimit == json.dumps(dict_long_payload)
    messages = retrieve_messages(40)
    assert messages[0]['payload'] == dict_long_payload


@pytest.mark.noparallel(reason='fails when run in parallel')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('hermes', 'services_list', 'nonexistingservice'),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
def test_non_existing_service(core_config_mock, caches_mock):
    """ MESSAGE (CORE): Test insert message to a non-existing service """
    truncate_messages()

    with pytest.raises(RucioException):
        add_message(event_type='NEW_DID', payload={'name': 'name',
                                                   'name_Y': 'scope_X',
                                                   'type': 'file'})
