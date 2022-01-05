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

import pytest

from rucio.common.exception import InvalidObject
from rucio.core.message import add_message, retrieve_messages, delete_messages, truncate_messages


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
def test_pop_messages(core_config_mock, caches_mock):
    """ MESSAGE (CORE): Test retrieve and delete messages """

    truncate_messages()
    list_messages = []
    for cnt in range(10):
        add_message(event_type='TEST', payload={'foo': True,
                                                'monty': 'python',
                                                'number': cnt})
        list_messages.append((cnt, 'influx'))
        list_messages.append((cnt, 'activemq'))
        list_messages.append((cnt, 'elastic'))

    messages = retrieve_messages(30)
    to_delete = []
    for message in messages:
        assert isinstance(message['payload'], dict)
        assert message['payload']['foo'] is True
        assert message['payload']['monty'] == 'python'
        assert message['payload']['number'] in list(range(10))
        to_delete.append({'id': message['id'],
                          'created_at': message['created_at'],
                          'updated_at': message['created_at'],
                          'payload': str(message['payload']),
                          'event_type': message['event_type']})
        list_messages.remove((message['payload']['number'], message['services']))

    assert list_messages == []

    delete_messages(to_delete)

    assert retrieve_messages() == []
