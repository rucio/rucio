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
# - Aristeidis Fkiaras, <aristeidis.fkiaras@cern.ch>, 2019
#
# PY3K COMPATIBLE

from nose.tools import assert_equal, assert_in, assert_raises

from rucio.client.didclient import DIDClient
from rucio.common.exception import KeyNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.did import add_did
from rucio.common.utils import generate_uuid
from rucio.common.config import config_get, config_get_bool
from rucio.core.did_meta_plugins import list_dids, get_metadata, set_metadata
from rucio.core.did_meta_plugins.json_meta import JSONDidMeta

from rucio.db.sqla.session import get_session


class TestDidMetaDidColumn():

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}
        self.tmp_scope = InternalScope('mock', **self.vo)
        self.root = InternalAccount('root', **self.vo)

    def test_add_did_meta(self):
        """ DID Meta (Hardcoded): Add did meta """
        did_name = 'mock_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key='project', value='data12_8TeV')
        assert_equal(get_metadata(scope=self.tmp_scope, name=did_name)['project'], 'data12_8TeV')

    def test_get_did_meta(self):
        """ DID Meta (Hardcoded): Get did meta """
        did_name = 'mock_did_%s' % generate_uuid()
        dataset_meta = {'project': 'data12_8TeV'}
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', meta=dataset_meta, account=self.root)
        assert_equal(get_metadata(scope=self.tmp_scope, name=did_name)['project'], 'data12_8TeV')

    def test_list_did_meta(self):
        """ DID Meta (Hardcoded): List did meta """
        dsns = []
        tmp_dsn1 = 'dsn_%s' % generate_uuid()

        dsns.append(tmp_dsn1)

        dataset_meta = {'project': 'data12_8TeV',
                        'run_number': 400000,
                        'stream_name': 'physics_CosmicCalo',
                        'prod_step': 'merge',
                        'datatype': 'NTUP_TRIG',
                        'version': 'f392_m920',
                        }

        add_did(scope=self.tmp_scope, name=tmp_dsn1, type="DATASET", account=self.root, meta=dataset_meta)

        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        dsns.append(tmp_dsn2)
        dataset_meta['run_number'] = 400001
        add_did(scope=self.tmp_scope, name=tmp_dsn2, type="DATASET", account=self.root, meta=dataset_meta)

        tmp_dsn3 = 'dsn_%s' % generate_uuid()
        dsns.append(tmp_dsn3)
        dataset_meta['stream_name'] = 'physics_Egamma'
        dataset_meta['datatype'] = 'NTUP_SMWZ'
        add_did(scope=self.tmp_scope, name=tmp_dsn3, type="DATASET", account=self.root, meta=dataset_meta)

        dids = list_dids(self.tmp_scope, {'project': 'data12_8TeV', 'version': 'f392_m920'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert_in(dsn, results)
        dsns.remove(tmp_dsn1)

        dids = list_dids(self.tmp_scope, {'project': 'data12_8TeV', 'run_number': 400001})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert_in(dsn, results)
        dsns.remove(tmp_dsn2)

        dids = list_dids(self.tmp_scope, {'project': 'data12_8TeV', 'stream_name': 'physics_Egamma', 'datatype': 'NTUP_SMWZ'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert_in(dsn, results)

        # with assert_raises(KeyNotFound):
        #     list_dids(tmp_scope, {'NotReallyAKey': 'NotReallyAValue'})


class TestDidMetaJSON():

    def setup(self):
        self.session = get_session()
        self.implemented = JSONDidMeta().json_implemented(self.session)
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}
        self.tmp_scope = InternalScope('mock', **self.vo)
        self.root = InternalAccount('root', **self.vo)

    def tearDown(self):
        self.session.commit()  # pylint: disable=no-member

    def test_add_did_meta(self):
        """ DID Meta (JSON): Add did meta """
        if not self.implemented:
            # For some oracle and sqlite version json support is not implemented
            return
        did_name = 'mock_did_%s' % generate_uuid()
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key=meta_key, value=meta_value)
        assert_equal(get_metadata(scope=self.tmp_scope, name=did_name, plugin='JSON')[meta_key], meta_value)

    def test_get_metadata(self):
        """ DID Meta (JSON): Get did meta """
        if not self.implemented:
            # For some oracle and sqlite version json support is not implemented
            return
        did_name = 'mock_did_%s' % generate_uuid()
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key=meta_key, value=meta_value)
        assert_equal(get_metadata(scope=self.tmp_scope, name=did_name, plugin='JSON')[meta_key], meta_value)

    def test_list_did_meta(self):
        """ DID Meta (JSON): List did meta """
        if not self.implemented:
            # For some oracle and sqlite version json support is not implemented
            return

        meta_key1 = 'my_key_%s' % generate_uuid()
        meta_key2 = 'my_key_%s' % generate_uuid()
        meta_value1 = 'my_value_%s' % generate_uuid()
        meta_value2 = 'my_value_%s' % generate_uuid()

        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=tmp_dsn1, type="DATASET", account=self.root)
        set_metadata(scope=self.tmp_scope, name=tmp_dsn1, key=meta_key1, value=meta_value1)

        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=tmp_dsn2, type="DATASET", account=self.root)
        set_metadata(scope=self.tmp_scope, name=tmp_dsn2, key=meta_key1, value=meta_value2)

        tmp_dsn3 = 'dsn_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=tmp_dsn3, type="DATASET", account=self.root)
        set_metadata(scope=self.tmp_scope, name=tmp_dsn3, key=meta_key2, value=meta_value1)

        tmp_dsn4 = 'dsn_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=tmp_dsn4, type="DATASET", account=self.root)
        set_metadata(scope=self.tmp_scope, name=tmp_dsn4, key=meta_key1, value=meta_value1)
        set_metadata(scope=self.tmp_scope, name=tmp_dsn4, key=meta_key2, value=meta_value2)

        dids = list_dids(self.tmp_scope, {meta_key1: meta_value1})
        results = []
        for d in dids:
            results.append(d)

        assert_equal(len(results), 2)
        # assert_equal(sorted([{'scope': tmp_scope, 'name': tmp_dsn1}, {'scope': tmp_scope, 'name': tmp_dsn4}]), sorted(results))
        assert_equal(sorted([tmp_dsn1, tmp_dsn4]), sorted(results))

        dids = list_dids(self.tmp_scope, {meta_key1: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert_equal(len(results), 1)
        # assert_equal([{'scope': (tmp_scope), 'name': str(tmp_dsn2)}], results)
        assert_equal([tmp_dsn2], results)

        dids = list_dids(self.tmp_scope, {meta_key2: meta_value1})
        results = []
        for d in dids:
            results.append(d)
        assert_equal(len(results), 1)
        # assert_equal([{'scope': (tmp_scope), 'name': tmp_dsn3}], results)
        assert_equal([tmp_dsn3], results)

        dids = list_dids(self.tmp_scope, {meta_key1: meta_value1, meta_key2: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert_equal(len(results), 1)
        # assert_equal([{'scope': (tmp_scope), 'name': tmp_dsn4}], results)
        assert_equal([tmp_dsn4], results)


class TestDidMetaClient():

    def setup(self):
        self.did_client = DIDClient()
        self.tmp_scope = 'mock'
        self.session = get_session()
        self.json_implemented = JSONDidMeta().json_implemented(self.session)

    def tearDown(self):
        self.session.commit()  # pylint: disable=no-member

    def test_set_metadata(self):
        """ META (CLIENTS) : Adds a fully set json column to a did, updates if some keys present """
        tmp_name = 'name_%s' % generate_uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=tmp_name, type="DATASET")

        # Test JSON case
        if self.json_implemented:
            # data1 = ["key1": "value_" + str(generate_uuid()), "key2": "value_" + str(generate_uuid()), "key3": "value_" + str(generate_uuid())]
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())
            value3 = "value_" + str(generate_uuid())
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key1", value=value1)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key2", value=value2)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key3", value=value3)

            metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="JSON")

            assert_equal(len(metadata), 3)
            assert_equal(metadata['key1'], value1)
            assert_equal(metadata['key2'], value2)
            assert_equal(metadata['key3'], value3)

        # Test DID_COLUMNS case
        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key='project', value='data12_12TeV')
        assert_equal(self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name)['project'], 'data12_12TeV')

    def test_delete_metadata(self):
        """ META (CLIENTS) : Deletes metadata key """
        tmp_name = 'name_%s' % generate_uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=tmp_name, type="DATASET")

        # Test JSON case
        if self.json_implemented:
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())
            value3 = "value_" + str(generate_uuid())

            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key1", value=value1)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key2", value=value2)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key3", value=value3)

            self.did_client.delete_metadata(scope=self.tmp_scope, name=tmp_name, key='key2')

            metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="JSON")
            assert_equal(len(metadata), 2)
            assert_equal(metadata['key1'], value1)
            assert_equal(metadata['key3'], value3)
            with assert_raises(KeyNotFound):
                self.did_client.delete_metadata(scope=self.tmp_scope, name=tmp_name, key="key9")

    def test_get_metadata(self):
        """ META (CLIENTS) : Gets all metadata for the given did """
        tmp_name = 'name_%s' % generate_uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=tmp_name, type="DATASET")

        # Test JSON case
        if self.json_implemented:
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())

            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key1", value=value1)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key2", value=value2)

            metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="JSON")

            assert_equal(len(metadata), 2)
            assert_equal(metadata['key1'], value1)
            assert_equal(metadata['key2'], value2)

        # Test DID_COLUMNS case
        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key='project', value='data12_14TeV')
        assert_equal(self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name)['project'], 'data12_14TeV')

        # Test Mixed case
        if self.json_implemented:
            all_metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="ALL")
            assert_equal(all_metadata['key1'], value1)
            assert_equal(all_metadata['key2'], value2)
            assert_equal(all_metadata['project'], "data12_14TeV")

    def test_list_dids_extended(self):
        """ META (CLIENTS) : Get all dids matching the values of the provided metadata keys """

        # Test did Columns use case
        dsns = []
        tmp_scope = 'mock'
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        dsns.append(tmp_dsn1)

        dataset_meta = {'project': 'data12_8TeV',
                        'run_number': 400000,
                        'stream_name': 'physics_CosmicCalo',
                        'prod_step': 'merge',
                        'datatype': 'NTUP_TRIG',
                        'version': 'f392_m920',
                        }
        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dsn1, meta=dataset_meta)
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        dsns.append(tmp_dsn2)
        dataset_meta['run_number'] = 400001
        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dsn2, meta=dataset_meta)

        tmp_dsn3 = 'dsn_%s' % generate_uuid()
        dsns.append(tmp_dsn3)
        dataset_meta['stream_name'] = 'physics_Egamma'
        dataset_meta['datatype'] = 'NTUP_SMWZ'
        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dsn3, meta=dataset_meta)

        dids = self.did_client.list_dids_extended(tmp_scope, {'project': 'data12_8TeV', 'version': 'f392_m920'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert_in(dsn, results)
        dsns.remove(tmp_dsn1)

        dids = self.did_client.list_dids_extended(tmp_scope, {'project': 'data12_8TeV', 'run_number': 400001})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert_in(dsn, results)
        dsns.remove(tmp_dsn2)

        dids = self.did_client.list_dids_extended(tmp_scope, {'project': 'data12_8TeV', 'stream_name': 'physics_Egamma', 'datatype': 'NTUP_SMWZ'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert_in(dsn, results)

        # Test JSON use case
        if self.json_implemented:
            did1 = 'name_%s' % generate_uuid()
            did2 = 'name_%s' % generate_uuid()
            did3 = 'name_%s' % generate_uuid()
            did4 = 'name_%s' % generate_uuid()

            key1 = 'key_1_%s' % generate_uuid()
            key2 = 'key_2_%s' % generate_uuid()
            key3 = 'key_3_%s' % generate_uuid()

            value1 = 'value_1_%s' % generate_uuid()
            value2 = 'value_2_%s' % generate_uuid()
            value3 = 'value_3_%s' % generate_uuid()
            value_not_1 = 'value_not_1_%s' % generate_uuid()
            value_not_2 = 'value_not_1_%s' % generate_uuid()
            value_unique = 'value_unique_%s' % generate_uuid()

            self.did_client.add_did(scope=tmp_scope, name=did1, type="DATASET")
            self.did_client.add_did(scope=tmp_scope, name=did2, type="DATASET")
            self.did_client.add_did(scope=tmp_scope, name=did3, type="DATASET")
            self.did_client.add_did(scope=tmp_scope, name=did4, type="DATASET")

            self.did_client.set_metadata(scope=tmp_scope, name=did1, key=key1, value=value1)
            self.did_client.set_metadata(scope=tmp_scope, name=did1, key=key2, value=value2)

            self.did_client.set_metadata(scope=tmp_scope, name=did2, key=key1, value=value1)
            self.did_client.set_metadata(scope=tmp_scope, name=did2, key=key2, value=value_not_2)
            self.did_client.set_metadata(scope=tmp_scope, name=did2, key=key3, value=value3)

            self.did_client.set_metadata(scope=tmp_scope, name=did3, key=key1, value=value_not_1)
            self.did_client.set_metadata(scope=tmp_scope, name=did3, key=key2, value=value2)
            self.did_client.set_metadata(scope=tmp_scope, name=did3, key=key3, value=value3)

            self.did_client.set_metadata(scope=tmp_scope, name=did4, key=key1, value=value1)
            self.did_client.set_metadata(scope=tmp_scope, name=did4, key=key2, value=value2)
            self.did_client.set_metadata(scope=tmp_scope, name=did4, key=key3, value=value_unique)

            # Key not there
            dids = self.did_client.list_dids_extended(tmp_scope, {'key45': 'value'})
            results = []
            for d in dids:
                results.append(d)
            assert_equal(len(results), 0)

            # Value not there
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: 'value_not_there'})
            results = []
            for d in dids:
                results.append(d)
            assert_equal(len(results), 0)

            # key1 = value1
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: value1})
            results = []
            for d in dids:
                results.append(d)
            assert_equal(len(results), 3)
            assert_in(did1, results)
            assert_in(did2, results)
            assert_in(did4, results)

            # key1, key2
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: value1, key2: value2})
            results = []
            for d in dids:
                results.append(d)
            assert_equal(len(results), 2)
            assert_in(did1, results)
            assert_in(did4, results)

            # key1, key2, key 3
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: value1, key2: value2, key3: value3})
            results = []
            for d in dids:
                results.append(d)
            assert_equal(len(results), 0)

            # key3 = unique value
            dids = self.did_client.list_dids_extended(tmp_scope, {key3: value_unique})
            results = []
            for d in dids:
                results.append(d)
            assert_equal(len(results), 1)
            assert_in(did4, results)
