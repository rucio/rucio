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

from copy import deepcopy

import pytest

from rucio.client.didclient import DIDClient
from rucio.common.exception import KeyNotFound
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did, delete_dids, set_metadata_bulk, set_dids_metadata_bulk
from rucio.core.did_meta_plugins import list_dids, get_metadata, set_metadata
from rucio.core.did_meta_plugins.mongo_meta import MongoDidMeta
from rucio.core.did_meta_plugins.postgres_meta import ExternalPostgresJSONDidMeta
from rucio.db.sqla.util import json_implemented
from rucio.tests.common import skip_rse_tests_with_accounts, did_name_generator


def skip_without_json():
    if not json_implemented():
        pytest.skip("JSON support is not implemented in this database")


class TestDidMetaDidColumn:

    @pytest.mark.dirty
    def test_add_did_meta(self, mock_scope, root_account):
        """ DID Meta (Hardcoded): Add did meta """
        did_name = did_name_generator('dataset')
        add_did(scope=mock_scope, name=did_name, did_type='DATASET', account=root_account)
        set_metadata(scope=mock_scope, name=did_name, key='project', value='data12_8TeV')
        assert get_metadata(scope=mock_scope, name=did_name)['project'] == 'data12_8TeV'

    @pytest.mark.dirty
    def test_get_did_meta(self, mock_scope, root_account):
        """ DID Meta (Hardcoded): Get did meta """
        did_name = did_name_generator('dataset')
        dataset_meta = {'project': 'data12_8TeV'}
        add_did(scope=mock_scope, name=did_name, did_type='DATASET', meta=dataset_meta, account=root_account)
        assert get_metadata(scope=mock_scope, name=did_name)['project'] == 'data12_8TeV'

    @pytest.mark.dirty
    def test_list_did_meta(self, mock_scope, root_account):
        """ DID Meta (Hardcoded): List did meta """
        dsns = []
        tmp_dsn1 = did_name_generator('dataset')

        dsns.append(tmp_dsn1)

        dataset_meta = {'project': 'data12_8TeV',
                        'run_number': 400000,
                        'stream_name': 'physics_CosmicCalo',
                        'prod_step': 'merge',
                        'datatype': 'NTUP_TRIG',
                        'version': 'f392_m920',
                        }

        add_did(scope=mock_scope, name=tmp_dsn1, did_type="DATASET", account=root_account, meta=dataset_meta)

        tmp_dsn2 = did_name_generator('dataset')
        dsns.append(tmp_dsn2)
        dataset_meta['run_number'] = 400001
        add_did(scope=mock_scope, name=tmp_dsn2, did_type="DATASET", account=root_account, meta=dataset_meta)

        tmp_dsn3 = did_name_generator('dataset')
        dsns.append(tmp_dsn3)
        dataset_meta['stream_name'] = 'physics_Egamma'
        dataset_meta['datatype'] = 'NTUP_SMWZ'
        add_did(scope=mock_scope, name=tmp_dsn3, did_type="DATASET", account=root_account, meta=dataset_meta)

        dids = list_dids(mock_scope, {'project': 'data12_8TeV', 'version': 'f392_m920'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results
        dsns.remove(tmp_dsn1)

        dids = list_dids(mock_scope, {'project': 'data12_8TeV', 'run_number': 400001})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results
        dsns.remove(tmp_dsn2)

        dids = list_dids(mock_scope, {'project': 'data12_8TeV', 'stream_name': 'physics_Egamma', 'datatype': 'NTUP_SMWZ'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results

        # with pytest.raises(KeyNotFound):
        #     list_dids(tmp_scope, {'NotReallyAKey': 'NotReallyAValue'})


class TestDidMetaJSON:

    @pytest.mark.dirty
    def test_add_did_meta(self, mock_scope, root_account):
        """ DID Meta (JSON): Add did meta """
        skip_without_json()

        did_name = did_name_generator('dataset')
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=mock_scope, name=did_name, did_type='DATASET', account=root_account)
        set_metadata(scope=mock_scope, name=did_name, key=meta_key, value=meta_value)
        assert get_metadata(scope=mock_scope, name=did_name, plugin='JSON')[meta_key] == meta_value

    @pytest.mark.dirty
    def test_get_metadata(self, mock_scope, root_account):
        """ DID Meta (JSON): Get did meta """
        skip_without_json()

        did_name = did_name_generator('dataset')
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=mock_scope, name=did_name, did_type='DATASET', account=root_account)
        set_metadata(scope=mock_scope, name=did_name, key=meta_key, value=meta_value)
        assert get_metadata(scope=mock_scope, name=did_name, plugin='JSON')[meta_key] == meta_value

    @pytest.mark.dirty
    def test_list_did_meta(self, mock_scope, root_account):
        """ DID Meta (JSON): List did meta """
        skip_without_json()

        meta_key1 = 'my_key_%s' % generate_uuid()
        meta_key2 = 'my_key_%s' % generate_uuid()
        meta_value1 = 'my_value_%s' % generate_uuid()
        meta_value2 = 'my_value_%s' % generate_uuid()

        tmp_dsn1 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn1, did_type="DATASET", account=root_account)
        set_metadata(scope=mock_scope, name=tmp_dsn1, key=meta_key1, value=meta_value1)

        tmp_dsn2 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn2, did_type="DATASET", account=root_account)
        set_metadata(scope=mock_scope, name=tmp_dsn2, key=meta_key1, value=meta_value2)

        tmp_dsn3 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn3, did_type="DATASET", account=root_account)
        set_metadata(scope=mock_scope, name=tmp_dsn3, key=meta_key2, value=meta_value1)

        tmp_dsn4 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn4, did_type="DATASET", account=root_account)
        set_metadata(scope=mock_scope, name=tmp_dsn4, key=meta_key1, value=meta_value1)
        set_metadata(scope=mock_scope, name=tmp_dsn4, key=meta_key2, value=meta_value2)

        dids = list_dids(mock_scope, {meta_key1: meta_value1})
        results = sorted(list(dids))

        assert len(results) == 2
        # assert sorted([{'scope': tmp_scope, 'name': tmp_dsn1}, {'scope': tmp_scope, 'name': tmp_dsn4}]) == sorted(results)
        expected = sorted([tmp_dsn1, tmp_dsn4])
        assert expected == results

        dids = list_dids(mock_scope, {meta_key1: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': str(tmp_dsn2)}] == results
        assert [tmp_dsn2] == results

        dids = list_dids(mock_scope, {meta_key2: meta_value1})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn3}] == results
        assert [tmp_dsn3] == results

        dids = list_dids(mock_scope, {meta_key1: meta_value1, meta_key2: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn4}] == results
        assert [tmp_dsn4] == results


@pytest.fixture
def mongo_meta():
    return MongoDidMeta(
        host='mongo',
        port=27017,
        db='test_db',
        collection='test_collection'
    )


@skip_rse_tests_with_accounts
class TestDidMetaMongo:

    @pytest.mark.dirty
    def test_set_get_metadata(self, mock_scope, root_account, mongo_meta):
        """ DID Meta (MONGO): Get/set did meta """

        did_name = did_name_generator('dataset')
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=mock_scope, name=did_name, did_type='DATASET', account=root_account)
        mongo_meta.set_metadata(scope=mock_scope, name=did_name, key=meta_key, value=meta_value)
        assert mongo_meta.get_metadata(scope=mock_scope, name=did_name)[meta_key] == meta_value

    @pytest.mark.dirty
    def test_list_did_meta(self, mock_scope, root_account, mongo_meta):
        """ DID Meta (MONGO): List did meta """

        meta_key1 = 'my_key_%s' % generate_uuid()
        meta_key2 = 'my_key_%s' % generate_uuid()
        meta_value1 = 'my_value_%s' % generate_uuid()
        meta_value2 = 'my_value_%s' % generate_uuid()

        tmp_dsn1 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn1, did_type="DATASET", account=root_account)
        mongo_meta.set_metadata(scope=mock_scope, name=tmp_dsn1, key=meta_key1, value=meta_value1)

        tmp_dsn2 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn2, did_type="DATASET", account=root_account)
        mongo_meta.set_metadata(scope=mock_scope, name=tmp_dsn2, key=meta_key1, value=meta_value2)

        tmp_dsn3 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn3, did_type="DATASET", account=root_account)
        mongo_meta.set_metadata(scope=mock_scope, name=tmp_dsn3, key=meta_key2, value=meta_value1)

        tmp_dsn4 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn4, did_type="DATASET", account=root_account)
        mongo_meta.set_metadata(scope=mock_scope, name=tmp_dsn4, key=meta_key1, value=meta_value1)
        mongo_meta.set_metadata(scope=mock_scope, name=tmp_dsn4, key=meta_key2, value=meta_value2)

        dids = mongo_meta.list_dids(mock_scope, {meta_key1: meta_value1})
        results = sorted(list(dids))

        assert len(results) == 2
        # assert sorted([{'scope': tmp_scope, 'name': tmp_dsn1}, {'scope': tmp_scope, 'name': tmp_dsn4}]) == sorted(results)
        expected = sorted([tmp_dsn1, tmp_dsn4])
        assert expected == results

        dids = mongo_meta.list_dids(mock_scope, {meta_key1: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': str(tmp_dsn2)}] == results
        assert [tmp_dsn2] == results

        dids = mongo_meta.list_dids(mock_scope, {meta_key2: meta_value1})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn3}] == results
        assert [tmp_dsn3] == results

        dids = mongo_meta.list_dids(mock_scope, {meta_key1: meta_value1, meta_key2: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn4}] == results
        assert [tmp_dsn4] == results


@pytest.fixture
def postgres_json_meta():
    return ExternalPostgresJSONDidMeta(
        host='postgres',
        port=5433,
        db='metadata',
        user='rucio',
        password='secret',
        db_schema='public',
        table='dids',
        table_is_managed=True,
        table_column_vo='vo',
        table_column_scope='scope',
        table_column_name='name',
        table_column_data='data',
    )


@pytest.mark.noparallel(reason='race condition on try-create table')
@skip_rse_tests_with_accounts
class TestDidMetaExternalPostgresJSON:

    @pytest.mark.dirty
    def test_set_get_metadata(self, mock_scope, root_account, postgres_json_meta):
        """ DID Meta (POSTGRES_JSON): Get/set did meta """

        did_name = did_name_generator('dataset')
        meta_key = 'my_key_%s' % generate_uuid()
        meta_value = 'my_value_%s' % generate_uuid()
        add_did(scope=mock_scope, name=did_name, did_type='DATASET', account=root_account)
        postgres_json_meta.set_metadata(scope=mock_scope, name=did_name, key=meta_key, value=meta_value)
        assert postgres_json_meta.get_metadata(scope=mock_scope, name=did_name)[meta_key] == meta_value

    @pytest.mark.dirty
    def test_list_did_meta(self, mock_scope, root_account, postgres_json_meta):
        """ DID Meta (POSTGRES_JSON): List did meta """

        meta_key1 = 'my_key_%s' % generate_uuid()
        meta_key2 = 'my_key_%s' % generate_uuid()
        meta_value1 = 'my_value_%s' % generate_uuid()
        meta_value2 = 'my_value_%s' % generate_uuid()

        tmp_dsn1 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn1, did_type="DATASET", account=root_account)
        postgres_json_meta.set_metadata(scope=mock_scope, name=tmp_dsn1, key=meta_key1, value=meta_value1)

        tmp_dsn2 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn2, did_type="DATASET", account=root_account)
        postgres_json_meta.set_metadata(scope=mock_scope, name=tmp_dsn2, key=meta_key1, value=meta_value2)

        tmp_dsn3 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn3, did_type="DATASET", account=root_account)
        postgres_json_meta.set_metadata(scope=mock_scope, name=tmp_dsn3, key=meta_key2, value=meta_value1)

        tmp_dsn4 = did_name_generator('dataset')
        add_did(scope=mock_scope, name=tmp_dsn4, did_type="DATASET", account=root_account)
        postgres_json_meta.set_metadata(scope=mock_scope, name=tmp_dsn4, key=meta_key1, value=meta_value1)
        postgres_json_meta.set_metadata(scope=mock_scope, name=tmp_dsn4, key=meta_key2, value=meta_value2)

        dids = postgres_json_meta.list_dids(mock_scope, {meta_key1: meta_value1})
        results = sorted(list(dids))

        assert len(results) == 2
        # assert sorted([{'scope': tmp_scope, 'name': tmp_dsn1}, {'scope': tmp_scope, 'name': tmp_dsn4}]) == sorted(results)
        expected = sorted([tmp_dsn1, tmp_dsn4])
        assert expected == results

        dids = postgres_json_meta.list_dids(mock_scope, {meta_key1: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': str(tmp_dsn2)}] == results
        assert [tmp_dsn2] == results

        dids = postgres_json_meta.list_dids(mock_scope, {meta_key2: meta_value1})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn3}] == results
        assert [tmp_dsn3] == results

        dids = postgres_json_meta.list_dids(mock_scope, {meta_key1: meta_value1, meta_key2: meta_value2})
        results = []
        for d in dids:
            results.append(d)
        assert len(results) == 1
        # assert [{'scope': (tmp_scope), 'name': tmp_dsn4}] == results
        assert [tmp_dsn4] == results


class TestDidMetaClient:

    @pytest.mark.dirty
    def test_set_metadata(self, mock_scope, did_client, db_session):
        """ META (CLIENTS) : Adds a fully set json column to a did, updates if some keys present """
        tmp_name = did_name_generator('dataset')
        scope = mock_scope.external
        did_client.add_did(scope=scope, name=tmp_name, did_type="DATASET")

        # Test JSON case
        if json_implemented(session=db_session):
            # data1 = ["key1": "value_" + str(generate_uuid()), "key2": "value_" + str(generate_uuid()), "key3": "value_" + str(generate_uuid())]
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())
            value3 = "value_" + str(generate_uuid())
            did_client.set_metadata(scope=scope, name=tmp_name, key="key1", value=value1)
            did_client.set_metadata(scope=scope, name=tmp_name, key="key2", value=value2)
            did_client.set_metadata(scope=scope, name=tmp_name, key="key3", value=value3)

            metadata = did_client.get_metadata(scope=scope, name=tmp_name, plugin="JSON")

            assert len(metadata) == 3
            assert metadata['key1'] == value1
            assert metadata['key2'] == value2
            assert metadata['key3'] == value3

        # Test DID_COLUMNS case
        did_client.set_metadata(scope=scope, name=tmp_name, key='project', value='data12_12TeV')
        assert did_client.get_metadata(scope=scope, name=tmp_name)['project'] == 'data12_12TeV'

    @pytest.mark.dirty
    def test_delete_metadata(self, mock_scope, did_client):
        """ META (CLIENTS) : Deletes metadata key """
        skip_without_json()
        scope = mock_scope.external
        tmp_name = did_name_generator('dataset')
        did_client.add_did(scope=scope, name=tmp_name, did_type="DATASET")

        value1 = "value_" + str(generate_uuid())
        value2 = "value_" + str(generate_uuid())
        value3 = "value_" + str(generate_uuid())

        did_client.set_metadata(scope=scope, name=tmp_name, key="key1", value=value1)
        did_client.set_metadata(scope=scope, name=tmp_name, key="key2", value=value2)
        did_client.set_metadata(scope=scope, name=tmp_name, key="key3", value=value3)

        did_client.delete_metadata(scope=scope, name=tmp_name, key='key2')

        metadata = did_client.get_metadata(scope=scope, name=tmp_name, plugin="JSON")
        assert len(metadata) == 2
        assert metadata['key1'] == value1
        assert metadata['key3'] == value3
        with pytest.raises(KeyNotFound):
            did_client.delete_metadata(scope=scope, name=tmp_name, key="key9")

    @pytest.mark.dirty
    def test_get_metadata(self, mock_scope, did_client, db_session):
        """ META (CLIENTS) : Gets all metadata for the given did """
        tmp_name = did_name_generator('dataset')
        scope = mock_scope.external
        did_client.add_did(scope=scope, name=tmp_name, did_type="DATASET")

        # Test JSON case
        if json_implemented(session=db_session):
            value1 = "value_" + str(generate_uuid())
            value2 = "value_" + str(generate_uuid())

            did_client.set_metadata(scope=scope, name=tmp_name, key="key1", value=value1)
            did_client.set_metadata(scope=scope, name=tmp_name, key="key2", value=value2)

            metadata = did_client.get_metadata(scope=scope, name=tmp_name, plugin="JSON")

            assert len(metadata) == 2
            assert metadata['key1'] == value1
            assert metadata['key2'] == value2

        # Test DID_COLUMNS case
        did_client.set_metadata(scope=scope, name=tmp_name, key='project', value='data12_14TeV')
        assert did_client.get_metadata(scope=scope, name=tmp_name)['project'] == 'data12_14TeV'

        # Test Mixed case
        if json_implemented(session=db_session):
            all_metadata = did_client.get_metadata(scope=scope, name=tmp_name, plugin="ALL")
            assert all_metadata['key1'] == value1
            assert all_metadata['key2'] == value2
            assert all_metadata['project'] == "data12_14TeV"

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='fails when run in parallel')
    def test_list_dids(self, did_client, db_session):
        """ META (CLIENTS) : Get all dids matching the values of the provided metadata keys """

        # Test did Columns use case
        dsns = []
        tmp_scope = 'mock'
        tmp_dsn1 = did_name_generator('dataset')
        dsns.append(tmp_dsn1)

        dataset_meta = {'project': 'data12_8TeV',
                        'run_number': 400000,
                        'stream_name': 'physics_CosmicCalo',
                        'prod_step': 'merge',
                        'datatype': 'NTUP_TRIG',
                        'version': 'f392_m920',
                        }
        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn1, meta=dataset_meta)
        tmp_dsn2 = did_name_generator('dataset')
        dsns.append(tmp_dsn2)
        dataset_meta['run_number'] = 400001
        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn2, meta=dataset_meta)

        tmp_dsn3 = did_name_generator('dataset')
        dsns.append(tmp_dsn3)
        dataset_meta['stream_name'] = 'physics_Egamma'
        dataset_meta['datatype'] = 'NTUP_SMWZ'
        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn3, meta=dataset_meta)

        dids = did_client.list_dids(tmp_scope, {'project': 'data12_8TeV', 'version': 'f392_m920'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results
        dsns.remove(tmp_dsn1)

        dids = did_client.list_dids(tmp_scope, {'project': 'data12_8TeV', 'run_number': 400001})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results
        dsns.remove(tmp_dsn2)

        dids = did_client.list_dids(tmp_scope, {'project': 'data12_8TeV', 'stream_name': 'physics_Egamma', 'datatype': 'NTUP_SMWZ'})
        results = []
        for d in dids:
            results.append(d)
        for dsn in dsns:
            assert dsn in results

        # Test JSON use case
        if json_implemented(session=db_session):
            did1 = did_name_generator('dataset')
            did2 = did_name_generator('dataset')
            did3 = did_name_generator('dataset')
            did4 = did_name_generator('dataset')

            key1 = 'key_1_%s' % generate_uuid()
            key2 = 'key_2_%s' % generate_uuid()
            key3 = 'key_3_%s' % generate_uuid()

            value1 = 'value_1_%s' % generate_uuid()
            value2 = 'value_2_%s' % generate_uuid()
            value3 = 'value_3_%s' % generate_uuid()
            value_not_1 = 'value_not_1_%s' % generate_uuid()
            value_not_2 = 'value_not_1_%s' % generate_uuid()
            value_unique = 'value_unique_%s' % generate_uuid()

            did_client.add_did(scope=tmp_scope, name=did1, did_type="DATASET")
            did_client.add_did(scope=tmp_scope, name=did2, did_type="DATASET")
            did_client.add_did(scope=tmp_scope, name=did3, did_type="DATASET")
            did_client.add_did(scope=tmp_scope, name=did4, did_type="DATASET")

            did_client.set_metadata(scope=tmp_scope, name=did1, key=key1, value=value1)
            did_client.set_metadata(scope=tmp_scope, name=did1, key=key2, value=value2)

            did_client.set_metadata(scope=tmp_scope, name=did2, key=key1, value=value1)
            did_client.set_metadata(scope=tmp_scope, name=did2, key=key2, value=value_not_2)
            did_client.set_metadata(scope=tmp_scope, name=did2, key=key3, value=value3)

            did_client.set_metadata(scope=tmp_scope, name=did3, key=key1, value=value_not_1)
            did_client.set_metadata(scope=tmp_scope, name=did3, key=key2, value=value2)
            did_client.set_metadata(scope=tmp_scope, name=did3, key=key3, value=value3)

            did_client.set_metadata(scope=tmp_scope, name=did4, key=key1, value=value1)
            did_client.set_metadata(scope=tmp_scope, name=did4, key=key2, value=value2)
            did_client.set_metadata(scope=tmp_scope, name=did4, key=key3, value=value_unique)

            # Key not there
            dids = did_client.list_dids(tmp_scope, {'key45': 'value'})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 0

            # Value not there
            dids = did_client.list_dids(tmp_scope, {key1: 'value_not_there'})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 0

            # key1 = value1
            dids = did_client.list_dids(tmp_scope, {key1: value1})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 3
            assert did1 in results
            assert did2 in results
            assert did4 in results

            # key1, key2
            dids = did_client.list_dids(tmp_scope, {key1: value1, key2: value2})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 2
            assert did1 in results
            assert did4 in results

            # key1, key2, key 3
            dids = did_client.list_dids(tmp_scope, {key1: value1, key2: value2, key3: value3})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 0

            # key3 = unique value
            dids = did_client.list_dids(tmp_scope, {key3: value_unique})
            results = []
            for d in dids:
                results.append(d)
            assert len(results) == 1
            assert did4 in results


@pytest.fixture
def testdid(vo, mock_scope, root_account):
    did_name = did_name_generator('dataset')
    didtype = 'DATASET'

    add_did(scope=mock_scope, name=did_name, did_type=didtype, account=root_account)
    yield {'name': did_name, 'scope': mock_scope}
    delete_dids(dids=[{'name': did_name, 'scope': mock_scope, 'did_type': didtype, 'purge_replicas': True}], account=root_account)


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


def test_set_dids_metadata_bulk_multi(did_factory):
    """ DID (CORE) : Test setting metadata in bulk with multiple key-values on multiple dids"""
    skip_without_json()
    nb_dids = 5
    dids = [did_factory.make_dataset() for _ in range(nb_dids)]

    for did in dids:
        testkeys = list(map(lambda i: 'testkey' + generate_uuid(), range(3)))
        testmeta = {key: key + 'value' for key in testkeys}
        did['meta'] = testmeta
    print(dids)

    set_dids_metadata_bulk(dids=dids, recursive=False)
    for did in dids:
        testmeta = did['meta']
        print('Metadata:', testmeta)
        meta = get_metadata(plugin="ALL", scope=did['scope'], name=did['name'])
        print('Metadata:', meta)
        for testkey in testmeta:
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


def test_set_dids_metadata_bulk_multi_client(did_factory, rucio_client):
    """ DID (CLIENT) : Test setting metadata in bulk with multiple key-values on multiple dids"""
    skip_without_json()
    nb_dids = 5
    dids = [did_factory.make_dataset() for _ in range(nb_dids)]
    for did in dids:
        testkeys = list(map(lambda i: 'testkey' + generate_uuid(), range(3)))
        testmeta = {key: key + 'value' for key in testkeys}
        did['meta'] = testmeta

    external_testdids = deepcopy(dids)
    for did in external_testdids:
        did['scope'] = did['scope'].external
    print(dids)
    print(external_testdids)

    result = rucio_client.set_dids_metadata_bulk(dids=external_testdids, recursive=False)
    assert result is True

    for did in dids:
        testmeta = did['meta']
        print('Metadata:', testmeta)
        meta = get_metadata(plugin="ALL", scope=did['scope'], name=did['name'])
        print('Metadata:', meta)
        for testkey in testmeta:
            assert testkey in meta and meta[testkey] == testmeta[testkey]
