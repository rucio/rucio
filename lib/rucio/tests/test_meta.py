# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Asket Agarwal, <asket.agarwal96@gmail.com>

from nose.tools import assert_equal, assert_in, assert_is_instance, assert_true, raises

from rucio.client.didclient import DIDClient
from rucio.client.metaclient import MetaClient
from rucio.common.exception import InvalidValueForKey, KeyNotFound, UnsupportedValueType
from rucio.common.utils import generate_uuid as uuid
from rucio.db.sqla.constants import DIDType


class TestMetaClient():

    def setup(self):
        self.meta_client = MetaClient()
        self.did_client = DIDClient()
        self.tmp_scope = 'mock'
        self.tmp_name = 'name_%s' % uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=self.tmp_name, type="DATASET")

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
        self.meta_client.add_key(key=key, key_type='ALL', value_type=unicode)
        self.meta_client.add_value(key=key, value=value)
        values = self.meta_client.list_values(key=key)
        assert_in(value, values)
        self.meta_client.add_value(key=key, value=1234)

    @raises(InvalidValueForKey)
    def xtest_add_value_with_regexp(self):
        """ META (CORE):  Add a new value to a key with a regexp constraint"""
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

    def xtest_add_key_mysql(self):
        """ META (CORE): Add a new key to test conversions on MySQL"""
        self.meta_client.add_key('datatype', DIDType.FILE)

    def xtest_add_metadata(self):
        """ META (CLIENTS) : Adds a fully set json column to a did, updates if some keys present """
        data = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
        self.meta_client._add_metadata(scope=self.tmp_scope, name=self.tmp_name, meta=data)

        data = {"key4": "value_" + str(uuid()), "key5": "value_" + str(uuid())}
        self.meta_client._add_metadata(scope=self.tmp_scope, name=self.tmp_name, meta=data)

    def xtest_delete_metadata(self):
        """ META (CLIENTS) : Deletes metadata key """
        data = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
        self.meta_client._add_metadata(scope=self.tmp_scope, name=self.tmp_name, meta=data)

        key = "key2"
        self.meta_client._delete_metadata(scope=self.tmp_scope, name=self.tmp_name, key=key)

    def xtest_get_metadata(self):
        """ META (CLIENTS) : Gets all metadata for the given did """
        data = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
        self.meta_client._add_metadata(scope=self.tmp_scope, name=self.tmp_name, meta=data)

        metadata = self.meta_client._get_metadata(scope=self.tmp_scope, name=self.tmp_name)
        assert_equal(metadata, data)

    def xtest_list_dids_by_metadata(self):
        """ META (CLIENTS) : Get all dids matching the values of the provided metadata keys """
        tmp_scope = 'temp'

        for i in range(5):
            tmp_name = 'name_%s' % str(i)
            self.did_client.add_did(scope=self.tmp_scope, name=self.tmp_name, type="DATASET", statuses={'monotonic': True})
            data = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
            self.meta_client._add_metadata(scope=tmp_scope, name=tmp_name, meta=data)

        temp_val = self.meta_client._get_metadata(scope=tmp_scope, name="name_1")

        select_query = {"key1": temp_val["key1"], "key2": temp_val["key2"]}
        dids = self.meta_client._list_dids_by_metadata(scope=tmp_scope, select=select_query)
        assert_is_instance(dids, list)
        assert_in("name_1", dids)

        select_query = {}
        dids = self.meta_client._list_dids_by_metadata(scope=tmp_scope, select=select_query)
        assert_is_instance(dids, list)
        assert_equal(len(dids), 5)
