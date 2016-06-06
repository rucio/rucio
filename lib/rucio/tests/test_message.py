# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

from nose.tools import assert_equal, assert_in, assert_is_instance, assert_raises

from rucio.core.message import add_message, retrieve_messages, delete_messages, truncate_messages
from rucio.common.exception import InvalidObject


class TestMessagesCore():

    def test_add_message(self):
        """ MESSAGE (CORE): Test valid and invalid message """

        truncate_messages()

        add_message(event_type='NEW_DID', payload={'name': 'name',
                                                   'name_Y': 'scope_X',
                                                   'type': 'file'})

        with assert_raises(InvalidObject):
            add_message(event_type='NEW_DID', payload={'name': 'name',
                                                       'name_Y': 'scope_X',
                                                       'type': int})

    def test_pop_messages(self):
        """ MESSAGE (CORE): Test retrieve and delete messages """

        truncate_messages()
        for i in xrange(10):
            add_message(event_type='TEST', payload={'foo': True,
                                                    'monty': 'python',
                                                    'number': i})

        tmp = retrieve_messages(10)
        to_delete = []
        for i in tmp:
            assert_is_instance(i['payload'], dict)
            assert_equal(i['payload']['foo'], True)
            assert_equal(i['payload']['monty'], 'python')
            assert_in(i['payload']['number'], xrange(100))
            to_delete.append(i['id'])
        delete_messages(to_delete)

        assert_equal(retrieve_messages(), [])
