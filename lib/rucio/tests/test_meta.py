# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2013
# - Shreyansh Khajanchi <shreyansh_k@live.com>, 2018
# - asket <asket.agarwal96@gmail.com>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

import unittest

import pytest

from rucio.client.metaclient import MetaClient
from rucio.common.exception import InvalidValueForKey, KeyNotFound, UnsupportedValueType, UnsupportedKeyType
from rucio.common.utils import generate_uuid as uuid
from rucio.core.meta import add_key
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import DIDType, KeyType


class TestMetaClient(unittest.TestCase):

    def setUp(self):
        self.meta_client = MetaClient()

    def xtest_add_and_list_keys(self):
        """ META (CLIENTS): Add a key and List all keys."""
        key = 'key_' + str(uuid())[:20]
        ret = self.meta_client.add_key(key=key, key_type='ALL')
        assert ret
        keys = self.meta_client.list_keys()
        assert isinstance(keys, list)
        assert key in keys

    def xtest_add_and_list_values(self):
        """ META (CLIENTS): Add a value and List all values."""
        key = 'key_' + str(uuid())[:20]
        value = 'value_' + str(uuid())

        ret = self.meta_client.add_key(key=key, key_type='ALL')
        assert ret

        ret = self.meta_client.add_value(key=key, value=value)

        values = self.meta_client.list_values(key=key)
        assert isinstance(values, list)
        assert value in values

    def xtest_add_value_with_type(self):
        """ META (CLIENTS):  Add a new value to a key with a type constraint"""
        key = 'key_' + str(uuid())[:20]
        value = 'value_' + str(uuid())
        self.meta_client.add_key(key=key, key_type='ALL', value_type=str)
        self.meta_client.add_value(key=key, value=value)
        values = self.meta_client.list_values(key=key)
        assert value in values
        self.meta_client.add_value(key=key, value=1234)

    def xtest_add_value_with_regexp(self):
        """ META (CLIENTS):  Add a new value to a key with a regexp constraint"""
        key = 'guid' + str(uuid())[:20]
        value = str(uuid())
        # regexp for uuid
        regexp = '[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}'
        self.meta_client.add_key(key=key, key_type='ALL', value_regexp=regexp)
        self.meta_client.add_value(key=key, value=value)
        values = self.meta_client.list_values(key=key)
        assert value in values
        with pytest.raises(InvalidValueForKey):
            self.meta_client.add_value(key=key, value='Nimportnawak')

    def xtest_add_unsupported_type(self):
        """ META (CLIENTS):  Add an unsupported value for type """
        key = 'key_' + str(uuid())[:20]
        with pytest.raises(UnsupportedValueType):
            self.meta_client.add_key(key=key, key_type='ALL', value_type=str)

    def xtest_add_value_to_bad_key(self):
        """ META (CLIENTS):  Add a new value to a non existing key """
        value = 'value_' + str(uuid())
        with pytest.raises(KeyNotFound):
            self.meta_client.add_value(key="Nimportnawak", value=value)

    def test_add_key(self):
        """ META (CLIENTS): Add a new key """
        types = [{'type': 'FILE', 'expected': KeyType.FILE},
                 {'type': 'ALL', 'expected': KeyType.ALL},
                 {'type': 'COLLECTION', 'expected': KeyType.COLLECTION},
                 {'type': 'DATASET', 'expected': KeyType.DATASET},
                 {'type': 'D', 'expected': KeyType.DATASET},
                 {'type': 'FILE', 'expected': KeyType.FILE},
                 {'type': 'F', 'expected': KeyType.FILE},
                 {'type': 'DERIVED', 'expected': KeyType.DERIVED},
                 {'type': 'C', 'expected': KeyType.CONTAINER}]

        for key_type in types:
            key_name = 'datatype%s' % str(uuid())
            self.meta_client.add_key(key_name, key_type['type'])
            stored_key_type = session.get_session().query(models.DIDKey).filter_by(key=key_name).one()['key_type']
            assert stored_key_type, key_type['expected']

        with pytest.raises(UnsupportedKeyType):
            self.meta_client.add_key('datatype', 'A')


class TestMetaCore():
    def test_add_key(self):
        """ META (CORE): Add a new key """
        types = [{'type': DIDType.FILE, 'expected': KeyType.FILE},
                 {'type': DIDType.CONTAINER, 'expected': KeyType.CONTAINER},
                 {'type': DIDType.DATASET, 'expected': KeyType.DATASET},
                 {'type': KeyType.ALL, 'expected': KeyType.ALL},
                 {'type': KeyType.DERIVED, 'expected': KeyType.DERIVED},
                 {'type': KeyType.FILE, 'expected': KeyType.FILE},
                 {'type': KeyType.COLLECTION, 'expected': KeyType.COLLECTION},
                 {'type': KeyType.CONTAINER, 'expected': KeyType.CONTAINER},
                 {'type': KeyType.DATASET, 'expected': KeyType.DATASET},
                 {'type': 'FILE', 'expected': KeyType.FILE},
                 {'type': 'ALL', 'expected': KeyType.ALL},
                 {'type': 'COLLECTION', 'expected': KeyType.COLLECTION},
                 {'type': 'DATASET', 'expected': KeyType.DATASET},
                 {'type': 'D', 'expected': KeyType.DATASET},
                 {'type': 'FILE', 'expected': KeyType.FILE},
                 {'type': 'F', 'expected': KeyType.FILE},
                 {'type': 'DERIVED', 'expected': KeyType.DERIVED},
                 {'type': 'C', 'expected': KeyType.CONTAINER}]

        for key_type in types:
            key_name = 'datatype%s' % str(uuid())
            add_key(key_name, key_type['type'])
            stored_key_type = session.get_session().query(models.DIDKey).filter_by(key=key_name).one()['key_type']
            assert stored_key_type, key_type['expected']

        with pytest.raises(UnsupportedKeyType):
            add_key('datatype', DIDType.ARCHIVE)

        with pytest.raises(UnsupportedKeyType):
            add_key('datatype', 'A')
