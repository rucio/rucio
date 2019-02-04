# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Asket Agarwal, <asket.agarwal96@gmail.com>
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from nose.tools import assert_equal, assert_is_instance, assert_in, assert_raises

from rucio.client.didclient import DIDClient
from rucio.common.utils import generate_uuid as uuid
from rucio.common.exception import RucioException, DataIdentifierNotFound, KeyNotFound


class TestDidMetaClient():

    def setup(self):
        self.did_client = DIDClient()
        self.tmp_scope = 'mock'
        self.tmp_name = 'name_%s' % uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=self.tmp_name, type="DATASET")

    def test_add_did_meta(self):
        """ META (CLIENTS) : Adds a fully set json column to a did, updates if some keys present """
        try:
            data1 = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
            self.did_client.add_did_meta(scope=self.tmp_scope, name=self.tmp_name, meta=data1)

            metadata = self.did_client.get_did_meta(scope=self.tmp_scope, name=self.tmp_name)
            assert_equal(len(metadata), 3)
            assert_equal(metadata, data1)

            data2 = {"key4": "value_" + str(uuid()), "key5": "value_" + str(uuid())}
            self.did_client.add_did_meta(scope=self.tmp_scope, name=self.tmp_name, meta=data2)

            metadata = self.did_client.get_did_meta(scope=self.tmp_scope, name=self.tmp_name)
            assert_equal(len(metadata), 5)
            assert_equal(metadata, dict(list(data1.items()) + list(data2.items())))

            with assert_raises(DataIdentifierNotFound):
                self.did_client.add_did_meta(scope=self.tmp_scope, name='Nimportnawak', meta=data1)

            data3 = {"key2": "value2", "key6": "value6"}
            self.did_client.add_did_meta(scope=self.tmp_scope, name=self.tmp_name, meta=data3)
            metadata = self.did_client.get_did_meta(scope=self.tmp_scope, name=self.tmp_name)
            assert_equal(len(metadata), 6)
            assert_equal(metadata["key2"], "value2")

        except RucioException:
            pass

    def test_delete_generic_metadata(self):
        """ META (CLIENTS) : Deletes metadata key """
        try:
            data = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
            self.did_client.add_did_meta(scope=self.tmp_scope, name=self.tmp_name, meta=data)

            key = "key2"
            self.did_client.delete_did_meta(scope=self.tmp_scope, name=self.tmp_name, key=key)
            metadata = self.did_client.get_did_meta(scope=self.tmp_scope, name=self.tmp_name)
            assert_equal(len(metadata), 2)

            with assert_raises(KeyNotFound):
                self.did_client.delete_did_meta(scope=self.tmp_scope, name=self.tmp_name, key="key9")

        except RucioException:
            pass

    def test_get_generic_metadata(self):
        """ META (CLIENTS) : Gets all metadata for the given did """
        try:
            data = {"key1": "value_" + str(uuid()), "key2": "value_" + str(uuid()), "key3": "value_" + str(uuid())}
            self.did_client.add_did_meta(scope=self.tmp_scope, name=self.tmp_name, meta=data)

            metadata = self.did_client.get_did_meta(scope=self.tmp_scope, name=self.tmp_name)
            assert_equal(metadata, data)

        except RucioException:
            pass

    def test_list_dids_by_generic_meta(self):
        """ META (CLIENTS) : Get all dids matching the values of the provided metadata keys """
        try:
            tmp_scope = 'mock'
            tmp_dids = []

            did1 = 'name_1'
            tmp_dids.append(did1)
            self.did_client.add_did(scope=tmp_scope, name=did1, type="DATASET")
            data = {"key1": "value1"}
            self.did_client.add_did_meta(scope=tmp_scope, name=did1, meta=data)

            did2 = 'name_2'
            tmp_dids.append(did2)
            self.did_client.add_did(scope=tmp_scope, name=did2, type="DATASET")
            data = {"key1": "value1", "key2": "value2"}
            self.did_client.add_did_meta(scope=tmp_scope, name=did2, meta=data)

            did3 = 'name_3'
            tmp_dids.append(did3)
            self.did_client.add_did(scope=tmp_scope, name=did3, type="DATASET")
            data = {"key1": "value1", "key2": "value2", "key3": "value3"}
            self.did_client.add_did_meta(scope=tmp_scope, name=did3, meta=data)

            did4 = 'name_4'
            tmp_dids.append(did4)
            self.did_client.add_did(scope=tmp_scope, name=did1, type="DATASET")
            data = {"key1": "value1", "key2": "value2", "key3": "value3", "key4": "value4"}
            self.did_client.add_did_meta(scope=tmp_scope, name=did1, meta=data)

            dids = self.did_client.list_dids_by_meta(scope=tmp_scope, select={"key1": "value1"})
            for did in tmp_dids:
                assert_in({'scope': 'mock', 'name': did}, dids)
            tmp_dids.remove(did1)

            dids = self.did_client.list_dids_by_meta(scope=tmp_scope, select={"key2": "value2"})
            for did in tmp_dids:
                assert_in({'scope': 'mock', 'name': did}, dids)
            tmp_dids.remove(did2)

            dids = self.did_client.list_dids_by_meta(scope=tmp_scope, select={"key3": "value3"})
            for did in tmp_dids:
                assert_in({'scope': 'mock', 'name': did}, dids)
            tmp_dids.remove(did3)

            dids = self.did_client.list_dids_by_meta(scope=tmp_scope, select={"key4": "value4"})
            for did in tmp_dids:
                assert_in({'scope': 'mock', 'name': did}, dids)
            tmp_dids.remove(did4)

            select_query = {"key1": "value1", "key2": "value2"}
            dids = self.did_client.list_dids_by_meta(scope=tmp_scope, select=select_query)
            assert_is_instance(dids, list)
            assert_equal(len(dids), 3)
            assert_in({'scope': 'mock', 'name': 'name_2'}, dids)

        except RucioException:
            pass
