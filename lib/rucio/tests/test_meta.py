# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from nose.tools import assert_in, assert_is_instance, assert_true, raises, assert_raises

from rucio.client.metaclient import MetaClient
from rucio.common.exception import InvalidValueForKey, KeyNotFound, UnsupportedValueType, UnsupportedKeyType
from rucio.common.utils import generate_uuid as uuid
from rucio.core.meta import add_key
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import DIDType, KeyType


class TestMetaClient():

    def setup(self):
        self.meta_client = MetaClient()

    def xtest_add_and_list_keys(self):
        """ META (CLIENTS): Add a key and List all keys."""
        key = 'key_' + str(uuid())[:20]
        ret = self.meta_client.add_key(key=key, key_type='ALL')
        assert_true(ret)
        keys = self.meta_client.list_keys()
        assert_is_instance(keys, list)
        assert_in(key, keys)

    def xtest_add_and_list_values(self):
        """ META (CLIENTS): Add a value and List all values."""
        key = 'key_' + str(uuid())[:20]
        value = 'value_' + str(uuid())

        ret = self.meta_client.add_key(key=key, key_type='ALL')
        assert_true(ret)

        ret = self.meta_client.add_value(key=key, value=value)

        values = self.meta_client.list_values(key=key)
        assert_is_instance(values, list)
        assert_in(value, values)

    @raises(InvalidValueForKey)
    def xtest_add_value_with_type(self):
        """ META (CLIENTS):  Add a new value to a key with a type constraint"""
        key = 'key_' + str(uuid())[:20]
        value = 'value_' + str(uuid())
        self.meta_client.add_key(key=key, key_type='ALL', value_type=str)
        self.meta_client.add_value(key=key, value=value)
        values = self.meta_client.list_values(key=key)
        assert_in(value, values)
        self.meta_client.add_value(key=key, value=1234)

    @raises(InvalidValueForKey)
    def xtest_add_value_with_regexp(self):
        """ META (CLIENTS):  Add a new value to a key with a regexp constraint"""
        key = 'guid' + str(uuid())[:20]
        value = str(uuid())
        # regexp for uuid
        regexp = '[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}'
        self.meta_client.add_key(key=key, key_type='ALL', value_regexp=regexp)
        self.meta_client.add_value(key=key, value=value)
        values = self.meta_client.list_values(key=key)
        assert_in(value, values)
        self.meta_client.add_value(key=key, value='Nimportnawak')

    @raises(UnsupportedValueType)
    def xtest_add_unsupported_type(self):
        """ META (CLIENTS):  Add an unsupported value for type """
        key = 'key_' + str(uuid())[:20]
        self.meta_client.add_key(key=key, key_type='ALL', value_type=str)

    @raises(KeyNotFound)
    def xtest_add_value_to_bad_key(self):
        """ META (CLIENTS):  Add a new value to a non existing key """
        value = 'value_' + str(uuid())
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
            assert_true(stored_key_type, key_type['expected'])

        with assert_raises(UnsupportedKeyType):
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
            assert_true(stored_key_type, key_type['expected'])

        with assert_raises(UnsupportedKeyType):
            add_key('datatype', DIDType.ARCHIVE)

        with assert_raises(UnsupportedKeyType):
            add_key('datatype', 'A')
