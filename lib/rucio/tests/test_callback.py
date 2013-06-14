# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from datetime import datetime
from re import compile

from nose.tools import assert_raises, assert_regexp_matches

from rucio.core.callback import add_callback
from rucio.common.exception import InvalidObject


class TestCallbackCoreApi():

    def test_add_callback(self):
        """ CALLBACK (CORE): Test add callback """
        callback_id = add_callback(event_type='NEW_DID', payload={'name': 'name', 'name_Y': 'scope_X', 'type': 'file', 'created_at':  datetime.utcnow()})
        assert_regexp_matches(callback_id, compile('[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}'))
        with assert_raises(InvalidObject):
                add_callback(event_type='NEW_DID', payload={'name': 'name', 'name_Y': 'scope_X', 'type':  int})
