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

from rucio.common.exception import InvalidValueForKey, RucioException, UnsupportedValueType, UnsupportedKeyType
from rucio.common.utils import generate_uuid as uuid
from rucio.core.meta_conventions import add_key
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import DIDType, KeyType


@pytest.mark.dirty
class TestMetaConventionsClient:

    def test_add_and_list_keys(self, rucio_client):
        """ META (CLIENTS): Add a key and List all keys."""
        key = 'key_' + str(uuid())[:20]
        ret = rucio_client.add_key(key=key, key_type='ALL')
        assert ret
        keys = rucio_client.list_keys()
        assert isinstance(keys, list)
        assert key in keys

    def test_add_and_list_values(self, rucio_client):
        """ META (CLIENTS): Add a value and List all values."""
        key = 'key_' + str(uuid())[:20]
        value = 'value_' + str(uuid())

        ret = rucio_client.add_key(key=key, key_type='ALL')
        assert ret

        ret = rucio_client.add_value(key=key, value=value)

        values = rucio_client.list_values(key=key)
        assert isinstance(values, list)
        assert value in values

    def test_add_value_with_type(self, rucio_client):
        """ META (CLIENTS):  Add a new value to a key with a type constraint"""
        key = 'key_' + str(uuid())[:20]
        value = 'value_' + str(uuid())
        rucio_client.add_key(key=key, key_type='ALL', value_type=str)
        rucio_client.add_value(key=key, value=value)
        values = rucio_client.list_values(key=key)
        assert value in values
        with pytest.raises(InvalidValueForKey):
            rucio_client.add_value(key=key, value=1234)

    def test_add_value_with_regexp(self, rucio_client):
        """ META (CLIENTS):  Add a new value to a key with a regexp constraint"""
        key = 'guid' + str(uuid())[:20]
        value = str(uuid())
        # regexp for uuid
        regexp = '[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}'
        rucio_client.add_key(key=key, key_type='ALL', value_regexp=regexp)
        rucio_client.add_value(key=key, value=value)
        values = rucio_client.list_values(key=key)
        assert value in values
        with pytest.raises(InvalidValueForKey):
            rucio_client.add_value(key=key, value='Nimportnawak')

    def test_add_unsupported_type(self, rucio_client):
        """ META (CLIENTS):  Add an unsupported value for type """
        key = 'key_' + str(uuid())[:20]
        with pytest.raises(UnsupportedValueType):
            rucio_client.add_key(key=key, key_type='ALL', value_type='bla')

    def test_add_value_to_bad_key(self, rucio_client):
        """ META (CLIENTS):  Add a new value to a non existing key """
        value = 'value_' + str(uuid())
        with pytest.raises(RucioException):
            rucio_client.add_value(key="Nimportnawak", value=value)

    def test_add_key(self, rucio_client):
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
            rucio_client.add_key(key_name, key_type['type'])
            stored_key_type = session.get_session().query(models.DIDMetaConventionsKey).filter_by(key=key_name).one()['key_type']
            assert stored_key_type, key_type['expected']

        with pytest.raises(UnsupportedKeyType):
            rucio_client.add_key('datatype', 'A')


@pytest.mark.dirty
def test_add_key():
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
        stored_key_type = session.get_session().query(models.DIDMetaConventionsKey).filter_by(key=key_name).one()['key_type']
        assert stored_key_type, key_type['expected']

    with pytest.raises(UnsupportedKeyType):
        add_key('datatype', DIDType.ARCHIVE)

    with pytest.raises(UnsupportedKeyType):
        add_key('datatype', 'A')
