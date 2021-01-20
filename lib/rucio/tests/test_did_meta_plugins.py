# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import unittest

import pytest

from rucio.client.didclient import DIDClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import KeyNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did, delete_dids, set_metadata_bulk
from rucio.core.did_meta_plugins import list_dids, get_metadata, set_metadata
from rucio.db.sqla.session import get_session
from rucio.db.sqla.util import json_implemented


def skip_without_json():
    if not json_implemented():
        pytest.skip("JSON support is not implemented in this database")


class TestDidMetaDidColumn(unittest.TestCase):

    def setUp(self):
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
        assert get_metadata(scope=self.tmp_scope, name=did_name)['project'] == 'data12_8TeV'

    def test_get_did_meta(self):
        """ DID Meta (Hardcoded): Get did meta """
        did_name = 'mock_did_%s' % generate_uuid()
        dataset_meta = {'project': 'data12_8TeV'}
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', meta=dataset_meta, account=self.root)
        assert get_metadata(scope=self.tmp_scope, name=did_name)['project'] == 'data12_8TeV'

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
            assert dsn in results
        dsns.remove(tmp_dsn1)

        dids = list_dids(self.tmp_scope, {'project': 'data12_8TeV', 'run_number': 400001})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results
        dsns.remove(tmp_dsn2)

        dids = list_dids(self.tmp_scope, {'project': 'data12_8TeV', 'stream_name': 'physics_Egamma', 'datatype': 'NTUP_SMWZ'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results

        # with pytest.raises(KeyNotFound):
        #     list_dids(tmp_scope, {'NotReallyAKey': 'NotReallyAValue'})


class TestDidMetaJSON(unittest.TestCase):

    def setUp(self):
        self.session = get_session()
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
        skip_without_json()

        did_name = 'mock_did_%s' % generate_uuid()
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key=meta_key, value=meta_value)
        assert get_metadata(scope=self.tmp_scope, name=did_name, plugin='JSON')[meta_key] == meta_value

    def test_get_metadata(self):
        """ DID Meta (JSON): Get did meta """
        skip_without_json()

        did_name = 'mock_did_%s' % generate_uuid()
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key=meta_key, value=meta_value)
        assert get_metadata(scope=self.tmp_scope, name=did_name, plugin='JSON')[meta_key] == meta_value

    def test_list_did_meta(self):
        """ DID Meta (JSON): List did meta """
        skip_without_json()

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
        results = sorted(list(dids))

        assert len(results) == 2
        # assert sorted([{'scope': tmp_scope, 'name': tmp_dsn1}, {'scope': tmp_scope, 'name': tmp_dsn4}]) == sorted(results)
        expected = sorted([tmp_dsn1, tmp_dsn4])
        assert expected == results

        dids = list_dids(self.tmp_scope, {meta_key1: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': str(tmp_dsn2)}] == results
        assert [tmp_dsn2] == results

        dids = list_dids(self.tmp_scope, {meta_key2: meta_value1})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn3}] == results
        assert [tmp_dsn3] == results

        dids = list_dids(self.tmp_scope, {meta_key1: meta_value1, meta_key2: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn4}] == results
        assert [tmp_dsn4] == results


class TestDidMetaClient(unittest.TestCase):

    def setUp(self):
        self.did_client = DIDClient()
        self.tmp_scope = 'mock'
        self.session = get_session()

    def tearDown(self):
        self.session.commit()  # pylint: disable=no-member

    def test_set_metadata(self):
        """ META (CLIENTS) : Adds a fully set json column to a did, updates if some keys present """
        tmp_name = 'name_%s' % generate_uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=tmp_name, type="DATASET")

        # Test JSON case
        if json_implemented(session=self.session):
            # data1 = ["key1": "value_" + str(generate_uuid()), "key2": "value_" + str(generate_uuid()), "key3": "value_" + str(generate_uuid())]
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())
            value3 = "value_" + str(generate_uuid())
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key1", value=value1)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key2", value=value2)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key3", value=value3)

            metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="JSON")

            assert len(metadata) == 3
            assert metadata['key1'] == value1
            assert metadata['key2'] == value2
            assert metadata['key3'] == value3

        # Test DID_COLUMNS case
        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key='project', value='data12_12TeV')
        assert self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name)['project'] == 'data12_12TeV'

    def test_delete_metadata(self):
        """ META (CLIENTS) : Deletes metadata key """
        skip_without_json()

        tmp_name = 'name_%s' % generate_uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=tmp_name, type="DATASET")

        value1 = "value_" + str(generate_uuid())
        value2 = "value_" + str(generate_uuid())
        value3 = "value_" + str(generate_uuid())

        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key1", value=value1)
        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key2", value=value2)
        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key3", value=value3)

        self.did_client.delete_metadata(scope=self.tmp_scope, name=tmp_name, key='key2')

        metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="JSON")
        assert len(metadata) == 2
        assert metadata['key1'] == value1
        assert metadata['key3'] == value3
        with pytest.raises(KeyNotFound):
            self.did_client.delete_metadata(scope=self.tmp_scope, name=tmp_name, key="key9")

    def test_get_metadata(self):
        """ META (CLIENTS) : Gets all metadata for the given did """
        tmp_name = 'name_%s' % generate_uuid()
        self.did_client.add_did(scope=self.tmp_scope, name=tmp_name, type="DATASET")

        # Test JSON case
        if json_implemented(session=self.session):
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())

            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key1", value=value1)
            self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key="key2", value=value2)

            metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="JSON")

            assert len(metadata) == 2
            assert metadata['key1'] == value1
            assert metadata['key2'] == value2

        # Test DID_COLUMNS case
        self.did_client.set_metadata(scope=self.tmp_scope, name=tmp_name, key='project', value='data12_14TeV')
        assert self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name)['project'] == 'data12_14TeV'

        # Test Mixed case
        if json_implemented(session=self.session):
            all_metadata = self.did_client.get_metadata(scope=self.tmp_scope, name=tmp_name, plugin="ALL")
            assert all_metadata['key1'] == value1
            assert all_metadata['key2'] == value2
            assert all_metadata['project'] == "data12_14TeV"

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
            assert dsn in results
        dsns.remove(tmp_dsn1)

        dids = self.did_client.list_dids_extended(tmp_scope, {'project': 'data12_8TeV', 'run_number': 400001})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results
        dsns.remove(tmp_dsn2)

        dids = self.did_client.list_dids_extended(tmp_scope, {'project': 'data12_8TeV', 'stream_name': 'physics_Egamma', 'datatype': 'NTUP_SMWZ'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results

        # Test JSON use case
        if json_implemented(session=self.session):
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
            assert len(results) == 0

            # Value not there
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: 'value_not_there'})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 0

            # key1 = value1
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: value1})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 3
            assert did1 in results
            assert did2 in results
            assert did4 in results

            # key1, key2
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: value1, key2: value2})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 2
            assert did1 in results
            assert did4 in results

            # key1, key2, key 3
            dids = self.did_client.list_dids_extended(tmp_scope, {key1: value1, key2: value2, key3: value3})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 0

            # key3 = unique value
            dids = self.did_client.list_dids_extended(tmp_scope, {key3: value_unique})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 1
            assert did4 in results


@pytest.fixture
def testdid(vo):
    did_name = 'testdid_%s' % generate_uuid()
    mock_scope = InternalScope('mock', vo=vo)
    didtype = 'DATASET'
    account = InternalAccount('root', vo=vo)

    add_did(scope=mock_scope, name=did_name, type=didtype, account=account)
    yield {'name': did_name, 'scope': mock_scope}
    delete_dids(dids=[{'name': did_name, 'scope': mock_scope, 'did_type': didtype, 'purge_replicas': True}], account=account)


def test_did_set_metadata_bulk_single(testdid):
    """ DID (CORE) : Test setting metadata in bulk with a single key-value pair """
    skip_without_json()

    testkey = 'testkey'
    testmeta = {testkey: 'testvalue'}

    set_metadata_bulk(meta=testmeta, recursive=False, **testdid)
    meta = get_metadata(plugin="ALL", **testdid)
    print('Metadata:', meta)

    assert testkey in meta and meta[testkey] == testmeta[testkey]


def test_did_set_metadata_bulk_multi(testdid):
    """ DID (CORE) : Test setting metadata in bulk with multiple key-values """
    skip_without_json()

    testkeys = list(map(lambda i: 'testkey' + str(i), range(3)))
    testmeta = {key: key + 'value' for key in testkeys}
    # let two keys have the same value
    testmeta[testkeys[1]] = testmeta[testkeys[0]]

    set_metadata_bulk(meta=testmeta, recursive=False, **testdid)
    meta = get_metadata(plugin="ALL", **testdid)
    print('Metadata:', meta)

    for testkey in testkeys:
        assert testkey in meta and meta[testkey] == testmeta[testkey]


def test_did_set_metadata_bulk_multi_client(testdid):
    """ DID (CLIENT) : Test setting metadata in bulk with multiple key-values """
    skip_without_json()

    testkeys = list(map(lambda i: 'testkey' + str(i), range(3)))
    testmeta = {key: key + 'value' for key in testkeys}
    # let two keys have the same value
    testmeta[testkeys[1]] = testmeta[testkeys[0]]

    didclient = DIDClient()
    external_testdid = testdid.copy()
    external_testdid['scope'] = testdid['scope'].external
    result = didclient.set_metadata_bulk(meta=testmeta, recursive=False, **external_testdid)
    assert result is True

    meta = get_metadata(plugin="ALL", **testdid)
    print('Metadata:', meta)

    for testkey in testkeys:
        assert testkey in meta and meta[testkey] == testmeta[testkey]
