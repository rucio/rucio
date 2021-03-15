# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import pytest

from rucio.common.exception import InvalidObject
from rucio.core.message import add_message, retrieve_messages, delete_messages, truncate_messages


@pytest.mark.noparallel(reason='fails when run in parallel')
class TestMessagesCore:

    def test_add_message(self):
        """ MESSAGE (CORE): Test valid and invalid message """

        truncate_messages()

        add_message(event_type='NEW_DID', payload={'name': 'name',
                                                   'name_Y': 'scope_X',
                                                   'type': 'file'})

        with pytest.raises(InvalidObject):
            add_message(event_type='NEW_DID', payload={'name': 'name',
                                                       'name_Y': 'scope_X',
                                                       'type': int})

    def test_pop_messages(self):
        """ MESSAGE (CORE): Test retrieve and delete messages """

        truncate_messages()
        for i in range(10):
            add_message(event_type='TEST', payload={'foo': True,
                                                    'monty': 'python',
                                                    'number': i})

        tmp = retrieve_messages(10)
        to_delete = []
        for i in tmp:
            assert isinstance(i['payload'], dict)
            assert i['payload']['foo'] is True
            assert i['payload']['monty'] == 'python'
            assert i['payload']['number'] in list(range(100))
            to_delete.append({'id': i['id'],
                              'created_at': i['created_at'],
                              'updated_at': i['created_at'],
                              'payload': str(i['payload']),
                              'event_type': i['event_type']})

        delete_messages(to_delete)

        assert retrieve_messages() == []
