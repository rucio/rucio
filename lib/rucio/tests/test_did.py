# -*- coding: utf-8 -*-
# Copyright CERN since 2012
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

from __future__ import print_function

from datetime import datetime, timedelta

import pytest

from rucio.api import did
from rucio.api import scope
from rucio.db.sqla.util import json_implemented
from rucio.common import exception
from rucio.common.exception import (DataIdentifierNotFound, DataIdentifierAlreadyExists,
                                    InvalidPath, KeyNotFound, UnsupportedOperation,
                                    UnsupportedStatus, ScopeNotFound, FileAlreadyExists, FileConsistencyMismatch)
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import (list_dids, add_did, delete_dids, get_did_atime, touch_dids, attach_dids, detach_dids,
                            get_metadata, set_metadata, get_did, get_did_access_cnt, add_did_to_followed,
                            get_users_following_did, remove_did_from_followed, set_status)
from rucio.core.replica import add_replica
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DIDType
from rucio.tests.common import rse_name_generator, scope_name_generator


def skip_without_json():
    if not json_implemented():
        pytest.skip("JSON support is not implemented in this database")


class TestDIDCore:

    def test_list_dids(self, vo):
        """ DATA IDENTIFIERS (CORE): List dids """
        for d in list_dids(scope=InternalScope('data13_hip', vo=vo), filters={'name': '*'}, did_type='collection'):
            print(d)

    def test_delete_dids(self, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Delete dids """
        dsns = [{'name': 'dsn_%s' % generate_uuid(),
                 'scope': mock_scope,
                 'purge_replicas': False,
                 'did_type': DIDType.DATASET} for i in range(5)]
        for dsn in dsns:
            add_did(scope=mock_scope, name=dsn['name'], did_type='DATASET', account=root_account)
        delete_dids(dids=dsns, account=root_account)

    @pytest.mark.dirty
    def test_touch_dids_atime(self, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Touch dids accessed_at timestamp"""
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()

        add_did(scope=mock_scope, name=tmp_dsn1, did_type=DIDType.DATASET, account=root_account)
        add_did(scope=mock_scope, name=tmp_dsn2, did_type=DIDType.DATASET, account=root_account)
        now = datetime.utcnow()

        now -= timedelta(microseconds=now.microsecond)
        assert get_did_atime(scope=mock_scope, name=tmp_dsn1) is None
        assert get_did_atime(scope=mock_scope, name=tmp_dsn2) is None

        touch_dids(dids=[{'scope': mock_scope, 'name': tmp_dsn1, 'type': DIDType.DATASET, 'accessed_at': now}])
        assert now == get_did_atime(scope=mock_scope, name=tmp_dsn1)
        assert get_did_atime(scope=mock_scope, name=tmp_dsn2) is None

    @pytest.mark.dirty
    def test_touch_dids_access_cnt(self, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Increase dids access_cnt"""
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()

        add_did(scope=mock_scope, name=tmp_dsn1, did_type=DIDType.DATASET, account=root_account)
        add_did(scope=mock_scope, name=tmp_dsn2, did_type=DIDType.DATASET, account=root_account)

        assert get_did_access_cnt(scope=mock_scope, name=tmp_dsn1) is None
        assert get_did_access_cnt(scope=mock_scope, name=tmp_dsn2) is None

        for i in range(100):
            touch_dids(dids=[{'scope': mock_scope, 'name': tmp_dsn1, 'type': DIDType.DATASET}])
        assert 100 == get_did_access_cnt(scope=mock_scope, name=tmp_dsn1)
        assert get_did_access_cnt(scope=mock_scope, name=tmp_dsn2) is None

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_update_dids(self, vo, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Update file size and checksum"""
        dsn = 'dsn_%s' % generate_uuid()
        lfn = 'lfn.%s' % str(generate_uuid())
        add_did(scope=mock_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)

        files = [{'scope': mock_scope, 'name': lfn,
                  'bytes': 724963570, 'adler32': '0cc737eb',
                  'meta': {'guid': str(generate_uuid()), 'events': 100}}]
        attach_dids(scope=mock_scope, name=dsn, rse_id=get_rse_id(rse='MOCK', vo=vo), dids=files, account=root_account)

        set_metadata(scope=mock_scope, name=lfn, key='adler32', value='0cc737ee')
        assert get_metadata(scope=mock_scope, name=lfn)['adler32'] == '0cc737ee'

        with pytest.raises(DataIdentifierNotFound):
            set_metadata(scope=mock_scope, name='Nimportnawak', key='adler32', value='0cc737ee')

        set_metadata(scope=mock_scope, name=lfn, key='bytes', value=724963577)
        assert get_metadata(scope=mock_scope, name=lfn)['bytes'] == 724963577

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_get_did_with_dynamic(self, vo, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Get did with dynamic resolve of size"""
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        tmp_dsn3 = 'dsn_%s' % generate_uuid()
        tmp_dsn4 = 'dsn_%s' % generate_uuid()

        rse_id = get_rse_id(rse='MOCK', vo=vo)

        add_did(scope=mock_scope, name=tmp_dsn1, did_type=DIDType.DATASET, account=root_account)
        add_replica(rse_id=rse_id, scope=mock_scope, name=tmp_dsn2, bytes_=10, account=root_account)
        add_replica(rse_id=rse_id, scope=mock_scope, name=tmp_dsn3, bytes_=10, account=root_account)
        attach_dids(scope=mock_scope, name=tmp_dsn1, dids=[{'scope': mock_scope, 'name': tmp_dsn2}, {'scope': mock_scope, 'name': tmp_dsn3}], account=root_account)

        add_did(scope=mock_scope, name=tmp_dsn4, did_type=DIDType.CONTAINER, account=root_account)
        attach_dids(scope=mock_scope, name=tmp_dsn4, dids=[{'scope': mock_scope, 'name': tmp_dsn1}], account=root_account)

        assert get_did(scope=mock_scope, name=tmp_dsn1, dynamic=True)['bytes'] == 20
        assert get_did(scope=mock_scope, name=tmp_dsn4, dynamic=True)['bytes'] == 20

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_reattach_dids(self, vo, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Repeatedly attach and detach DIDs """
        parent_name = 'parent_%s' % generate_uuid()
        add_did(scope=mock_scope, name=parent_name, did_type=DIDType.DATASET, account=root_account)

        child_name = 'child_%s' % generate_uuid()
        files = [{'scope': mock_scope, 'name': child_name,
                  'bytes': 12345, 'adler32': '0cc737eb'}]

        rse_id = get_rse_id('MOCK', vo=vo)
        attach_dids(scope=mock_scope, name=parent_name, rse_id=rse_id, dids=files, account=root_account)

        detach_dids(scope=mock_scope, name=parent_name, dids=files)

        attach_dids(scope=mock_scope, name=parent_name, rse_id=rse_id, dids=files, account=root_account)

        detach_dids(scope=mock_scope, name=parent_name, dids=files)

    @pytest.mark.dirty
    def test_add_did_to_followed(self, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Mark a did as followed """
        dsn = 'dsn_%s' % generate_uuid()

        add_did(scope=mock_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        add_did_to_followed(scope=mock_scope, name=dsn, account=root_account)
        users = get_users_following_did(scope=mock_scope, name=dsn)
        rows = 0
        for user in users:
            rows += 1

        assert rows == 1

    @pytest.mark.dirty
    def test_get_users_following_did(self, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Get the list of users following a did """
        dsn = 'dsn_%s' % generate_uuid()

        add_did(scope=mock_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        add_did_to_followed(scope=mock_scope, name=dsn, account=root_account)

        users = get_users_following_did(scope=mock_scope, name=dsn)
        rows = 0
        for user in users:
            rows += 1

        assert rows == 1

    @pytest.mark.dirty
    def test_remove_did_from_followed(self, mock_scope, root_account):
        """ DATA IDENTIFIERS (CORE): Mark a did as not followed """
        dsn = 'dsn_%s' % generate_uuid()

        add_did(scope=mock_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        add_did_to_followed(scope=mock_scope, name=dsn, account=root_account)

        users = get_users_following_did(scope=mock_scope, name=dsn)
        rows = 0
        for user in users:
            rows += 1

        assert rows == 1

        remove_did_from_followed(scope=mock_scope, name=dsn, account=root_account)

        users = get_users_following_did(scope=mock_scope, name=dsn)
        rows = 0
        for user in users:
            rows += 1

        assert rows == 0


class TestDIDApi:

    @pytest.mark.dirty
    def test_list_new_dids(self, vo):
        """ DATA IDENTIFIERS (API): List new identifiers """
        tmp_scope = scope_name_generator()
        tmp_dsn = 'dsn_%s' % generate_uuid()
        scope.add_scope(tmp_scope, 'jdoe', 'jdoe', vo=vo)
        for i in range(0, 5):
            did.add_did(scope=tmp_scope, name='%s-%i' % (tmp_dsn, i), did_type='DATASET', issuer='root', vo=vo)
        for i in did.list_new_dids('DATASET', vo=vo):
            assert i != {}
            assert i['did_type'] == DIDType.DATASET
            break
        for i in did.list_new_dids(vo=vo):
            assert i != {}
            break

    @pytest.mark.dirty
    def test_update_new_dids(self, vo):
        """ DATA IDENTIFIERS (API): List new identifiers and update the flag new """
        tmp_scope = scope_name_generator()
        tmp_dsn = 'dsn_%s' % generate_uuid()
        scope.add_scope(tmp_scope, 'jdoe', 'jdoe', vo=vo)
        dids = []
        for i in range(0, 5):
            d = {'scope': tmp_scope, 'name': '%s-%i' % (tmp_dsn, i), 'did_type': DIDType.DATASET}
            did.add_did(scope=tmp_scope, name='%s-%i' % (tmp_dsn, i), did_type='DATASET', issuer='root', vo=vo)
            dids.append(d)
        st = did.set_new_dids(dids, None, vo=vo)
        assert st
        with pytest.raises(DataIdentifierNotFound):
            did.set_new_dids([{'scope': 'dummyscope', 'name': 'dummyname', 'did_type': DIDType.DATASET}], None, vo=vo)


class TestDIDClients:

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_dids(self, did_client, replica_client, scope_client):
        """ DATA IDENTIFIERS (CLIENT): List dids by pattern."""
        tmp_scope = scope_name_generator()
        tmp_files = []
        tmp_files.append('file_a_1%s' % generate_uuid())
        tmp_files.append('file_a_2%s' % generate_uuid())
        tmp_files.append('file_b_1%s' % generate_uuid())
        tmp_rse = 'MOCK'

        scope_client.add_scope('jdoe', tmp_scope)
        for tmp_file in tmp_files:
            replica_client.add_replica(tmp_rse, tmp_scope, tmp_file, 1, '0cc737eb')

        results = []
        for result in did_client.list_dids(tmp_scope, {'name': 'file_a_*'}, did_type='file'):
            results.append(result)
        assert len(results) == 2
        results = []
        for result in did_client.list_dids(tmp_scope, {'name': 'file_a_1*'}, did_type='file'):
            results.append(result)
        assert len(results) == 1
        results = []
        for result in did_client.list_dids(tmp_scope, {'name': 'file_*_1*'}, did_type='file'):
            results.append(result)
        assert len(results) == 2
        results = []
        for result in did_client.list_dids(tmp_scope, {'name': 'file*'}, did_type='file'):
            results.append(result)
        assert len(results) == 3
        results = []

        filters = {'name': 'file*', 'created_after': datetime.utcnow() - timedelta(hours=1)}
        for result in did_client.list_dids(tmp_scope, filters):
            results.append(result)
        assert len(results) == 0
        with pytest.raises(UnsupportedOperation):
            did_client.list_dids(tmp_scope, {'name': 'file*'}, did_type='whateverytype')

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined scope names')
    def test_list_recursive(self, did_client, scope_client):
        """ DATA IDENTIFIERS (CLIENT): List did recursive """
        # Create nested containers and datast
        tmp_scope_1 = ('list-did-recursive-%s' % generate_uuid())[:25]
        tmp_scope_2 = ('list-did-recursive-%s' % generate_uuid())[:25]
        scope_client.add_scope('root', tmp_scope_1)
        scope_client.add_scope('root', tmp_scope_2)

        tmp_container_1 = 'container_%s' % generate_uuid()
        did_client.add_container(scope=tmp_scope_1, name=tmp_container_1)

        tmp_container_2 = 'container_%s' % generate_uuid()
        did_client.add_container(scope=tmp_scope_1, name=tmp_container_2)

        tmp_dataset_1 = 'dataset_%s' % generate_uuid()
        did_client.add_dataset(scope=tmp_scope_2, name=tmp_dataset_1)

        tmp_dataset_2 = 'dataset_%s' % generate_uuid()
        did_client.add_dataset(scope=tmp_scope_1, name=tmp_dataset_2)

        did_client.attach_dids(scope=tmp_scope_1, name=tmp_container_1, dids=[{'scope': tmp_scope_2, 'name': tmp_dataset_1}])
        did_client.attach_dids(scope=tmp_scope_1, name=tmp_container_2, dids=[{'scope': tmp_scope_1, 'name': tmp_dataset_2}])
        did_client.attach_dids(scope=tmp_scope_1, name=tmp_container_1, dids=[{'scope': tmp_scope_1, 'name': tmp_container_2}])

        # List DIDs not recursive - only the first container is expected
        dids = [str(did) for did in did_client.list_dids(scope=tmp_scope_1, recursive=False, did_type='all', filters={'name': tmp_container_1})]
        assert dids == [tmp_container_1]

        # List DIDs recursive - first container and all attached collections are expected
        dids = [str(did) for did in did_client.list_dids(scope=tmp_scope_1, recursive=True, did_type='all', filters={'name': tmp_container_1})]
        assert tmp_container_1 in dids
        assert tmp_container_2 in dids
        assert tmp_dataset_1 in dids
        assert tmp_dataset_2 in dids
        assert len(dids) == 4

        # List DIDs recursive - only containers are expected
        dids = [str(did) for did in did_client.list_dids(scope=tmp_scope_1, recursive=True, did_type='container', filters={'name': tmp_container_1})]
        assert tmp_container_1 in dids
        assert tmp_container_2 in dids
        assert tmp_dataset_1 not in dids
        assert tmp_dataset_2 not in dids
        assert len(dids) == 2

    @pytest.mark.dirty
    def test_list_by_metadata(self, did_client):
        """ DATA IDENTIFIERS (CLIENT): List did with metadata"""
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
        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn1, meta=dataset_meta)
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        dsns.append(tmp_dsn2)
        dataset_meta['run_number'] = 400001
        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn2, meta=dataset_meta)

        tmp_dsn3 = 'dsn_%s' % generate_uuid()
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

        with pytest.raises(KeyNotFound):
            did_client.list_dids(tmp_scope, {'NotReallyAKey': 'NotReallyAValue'})

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_add_did(self, vo, did_client):
        """ DATA IDENTIFIERS (CLIENT): Add, populate, list did content and create a sample"""
        tmp_scope = 'mock'
        tmp_rse = 'MOCK'
        tmp_dsn = 'dsn_%s' % generate_uuid()
        root = InternalAccount('root', vo=vo)
        set_local_account_limit(root, get_rse_id('MOCK', vo=vo), -1)
        set_local_account_limit(root, get_rse_id('CERN-PROD_TZERO', vo=vo), -1)

        # PFN example: rfio://castoratlas.cern.ch/castor/cern.ch/grid/atlas/tzero/xx/xx/xx/filename
        dataset_meta = {'project': 'data13_hip',
                        'run_number': 300000,
                        'stream_name': 'physics_CosmicCalo',
                        'prod_step': 'merge',
                        'datatype': 'NTUP_TRIG',
                        'version': 'f392_m927',
                        }
        rules = [{'copies': 1, 'rse_expression': 'MOCK', 'account': 'root'}]

        with pytest.raises(ScopeNotFound):
            did_client.add_dataset(scope='Nimportnawak', name=tmp_dsn, statuses={'monotonic': True}, meta=dataset_meta, rules=rules)

        files = [{'scope': InternalScope(tmp_scope, vo=vo), 'name': 'lfn.%(tmp_dsn)s.' % locals() + str(generate_uuid()), 'bytes': 724963570, 'adler32': '0cc737eb'}, ]
        with pytest.raises(DataIdentifierNotFound):
            did_client.add_dataset(scope=tmp_scope, name=tmp_dsn, statuses={'monotonic': True}, meta=dataset_meta, rules=rules, files=files)

        with pytest.raises(DataIdentifierNotFound):
            did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dsn, files=files)

        files = []
        for i in range(5):
            lfn = 'lfn.%(tmp_dsn)s.' % locals() + str(generate_uuid())
            pfn = 'mock://localhost/tmp/rucio_rse/%(project)s/%(version)s/%(prod_step)s' % dataset_meta
            # it doesn't work with mock: TBF
            # pfn = 'srm://mock2.com:2880/pnfs/rucio/disk-only/scratchdisk/rucio_tests/%(project)s/%(version)s/%(prod_step)s' % dataset_meta
            pfn += '%(tmp_dsn)s/%(lfn)s' % locals()
            file_meta = {'guid': str(generate_uuid()), 'events': 10}
            files.append({'scope': InternalScope(tmp_scope, vo=vo), 'name': lfn,
                          'bytes': 724963570, 'adler32': '0cc737eb',
                          'pfn': pfn, 'meta': file_meta})

        rules = [{'copies': 1, 'rse_expression': 'CERN-PROD_TZERO', 'lifetime': timedelta(days=2), 'account': 'root'}]

        with pytest.raises(InvalidPath):
            did_client.add_dataset(scope=tmp_scope, name=tmp_dsn, statuses={'monotonic': True}, meta=dataset_meta, rules=rules, files=files, rse=tmp_rse)

        files_without_pfn = [{'scope': i['scope'], 'name': i['name'], 'bytes': i['bytes'], 'adler32': i['adler32'], 'meta': i['meta']} for i in files]
        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn, statuses={'monotonic': True}, meta=dataset_meta, rules=rules, files=files_without_pfn, rse=tmp_rse)

        with pytest.raises(DataIdentifierAlreadyExists):
            did_client.add_dataset(scope=tmp_scope, name=tmp_dsn, files=files, rse=tmp_rse)

        files = []
        for i in range(5):
            lfn = '%(tmp_dsn)s.' % locals() + str(generate_uuid())
            pfn = 'mock://localhost/tmp/rucio_rse/%(project)s/%(version)s/%(prod_step)s' % dataset_meta
            # it doesn't work with mock: TBF
            # pfn = 'srm://mock2.com:2880/pnfs/rucio/disk-only/scratchdisk/rucio_tests/%(project)s/%(version)s/%(prod_step)s' % dataset_meta
            pfn += '%(tmp_dsn)s/%(lfn)s' % locals()
            file_meta = {'guid': str(generate_uuid()), 'events': 100}
            files.append({'scope': InternalScope(tmp_scope, vo=vo), 'name': lfn,
                          'bytes': 724963570, 'adler32': '0cc737eb',
                          'pfn': pfn, 'meta': file_meta})
        rules = [{'copies': 1, 'rse_expression': 'CERN-PROD_TZERO', 'lifetime': timedelta(days=2)}]

        with pytest.raises(InvalidPath):
            did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dsn, files=files, rse=tmp_rse)
        files_without_pfn = [{'scope': i['scope'], 'name': i['name'], 'bytes': i['bytes'], 'adler32': i['adler32'], 'meta': i['meta']} for i in files]
        did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dsn, files=files_without_pfn, rse=tmp_rse)

        did_client.close(scope=tmp_scope, name=tmp_dsn)

        tmp_dsn_output = 'dsn_%s' % generate_uuid()
        did_client.create_did_sample(input_scope=tmp_scope, input_name=tmp_dsn, output_scope=tmp_scope, output_name=tmp_dsn_output, nbfiles=2)
        files = [f for f in did_client.list_files(scope=tmp_scope, name=tmp_dsn_output)]
        assert len(files) == 2

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_attach_dids_to_dids(self, did_client):
        """ DATA IDENTIFIERS (CLIENT): Attach dids to dids"""
        tmp_scope = 'mock'
        tmp_rse = 'MOCK'
        nb_datasets = 5
        nb_files = 5
        attachments, dsns = list(), list()
        guid_to_query = None
        dsn = {}
        for i in range(nb_datasets):
            attachment = {}
            attachment['scope'] = tmp_scope
            attachment['name'] = 'dsn.%s' % str(generate_uuid())
            attachment['rse'] = tmp_rse
            files = []
            for i in range(nb_files):
                files.append({'scope': tmp_scope, 'name': 'lfn.%s' % str(generate_uuid()),
                              'bytes': 724963570, 'adler32': '0cc737eb',
                              'meta': {'guid': str(generate_uuid()), 'events': 100}})
            attachment['dids'] = files
            guid_to_query = files[0]['meta']['guid']
            dsn = {'scope': tmp_scope, 'name': attachment['name']}
            dsns.append(dsn)
            attachments.append(attachment)

        did_client.add_datasets(dsns=dsns)
        did_client.attach_dids_to_dids(attachments=attachments)
        dsns_l = [i for i in did_client.get_dataset_by_guid(guid_to_query)]

        assert [dsn] == dsns_l

        cnt_name = 'cnt_%s' % generate_uuid()
        did_client.add_container(scope='mock', name=cnt_name)
        with pytest.raises(UnsupportedOperation):
            did_client.attach_dids_to_dids([{'scope': 'mock', 'name': cnt_name, 'rse': tmp_rse, 'dids': attachment['dids']}])

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_add_files_to_datasets(self, did_client):
        """ DATA IDENTIFIERS (CLIENT): Add files to Datasets"""
        tmp_scope = 'mock'
        tmp_rse = 'MOCK'
        dsn1 = 'dsn.%s' % str(generate_uuid())
        dsn2 = 'dsn.%s' % str(generate_uuid())
        meta = {'transient': True}
        files1, files2, nb_files = [], [], 5
        for i in range(nb_files):
            files1.append({'scope': tmp_scope, 'name': 'lfn.%s' % str(generate_uuid()),
                           'bytes': 724963570, 'adler32': '0cc737eb',
                           'meta': {'guid': str(generate_uuid()), 'events': 100}})
            files2.append({'scope': tmp_scope, 'name': 'lfn.%s' % str(generate_uuid()),
                           'bytes': 724963570, 'adler32': '0cc737eb',
                           'meta': {'guid': str(generate_uuid()), 'events': 100}})

        did_client.add_dataset(scope=tmp_scope, name=dsn1, files=files1,
                               rse=tmp_rse, meta=meta)
        did_client.add_dataset(scope=tmp_scope, name=dsn2, files=files2,
                               rse=tmp_rse, meta=meta)

        attachments = [{'scope': tmp_scope, 'name': dsn1, 'dids': files2, 'rse': tmp_rse},
                       {'scope': tmp_scope, 'name': dsn2, 'dids': files1, 'rse': tmp_rse}]

        did_client.add_files_to_datasets(attachments)

        files = [f for f in did_client.list_files(scope=tmp_scope, name=dsn1)]
        assert len(files) == 10

        with pytest.raises(FileAlreadyExists):
            did_client.add_files_to_datasets(attachments)

        for attachment in attachments:
            for i in range(nb_files):
                attachment['dids'].append({'scope': tmp_scope,
                                           'name': 'lfn.%s' % str(generate_uuid()),
                                           'bytes': 724963570,
                                           'adler32': '0cc737eb',
                                           'meta': {'guid': str(generate_uuid()),
                                                    'events': 100}})

        did_client.add_files_to_datasets(attachments, ignore_duplicate=True)

        files = [f for f in did_client.list_files(scope=tmp_scope, name=dsn1)]
        assert len(files) == 15

        # Corrupt meta-data
        files = []
        for attachment in attachments:
            for file in attachment['dids']:
                file['bytes'] = 1000
                break

        with pytest.raises(FileConsistencyMismatch):
            did_client.add_files_to_datasets(attachments, ignore_duplicate=True)

    @pytest.mark.dirty
    def test_add_dataset(self, did_client):
        """ DATA IDENTIFIERS (CLIENT): Add dataset """
        tmp_scope = 'mock'
        tmp_dsn = 'dsn_%s' % generate_uuid()

        did_client.add_dataset(scope=tmp_scope, name=tmp_dsn, meta={'project': 'data13_hip'})

        did = did_client.get_did(tmp_scope, tmp_dsn)

        assert did['scope'] == tmp_scope
        assert did['name'] == tmp_dsn

        with pytest.raises(DataIdentifierNotFound):
            did_client.get_did('i_dont_exist', 'neither_do_i')

    @pytest.mark.dirty
    def test_add_datasets(self, did_client):
        """ DATA IDENTIFIERS (CLIENT): Bulk add datasets """
        tmp_scope = 'mock'
        dsns = list()
        for i in range(500):
            tmp_dsn = {'name': 'dsn_%s' % generate_uuid(), 'scope': tmp_scope, 'meta': {'project': 'data13_hip'}, 'account': 'root'}
            dsns.append(tmp_dsn)
        did_client.add_datasets(dsns)

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_exists(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): Check if data identifier exists """
        tmp_scope = 'mock'
        tmp_file = 'file_%s' % generate_uuid()
        tmp_rse = 'MOCK'

        replica_client.add_replica(tmp_rse, tmp_scope, tmp_file, 1, '0cc737eb')

        did = did_client.get_did(tmp_scope, tmp_file)

        assert did['scope'] == tmp_scope
        assert did['name'] == tmp_file

        with pytest.raises(DataIdentifierNotFound):
            did_client.get_did('i_dont_exist', 'neither_do_i')

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_did_hierarchy(self, did_client, replica_client, scope_client):
        """ DATA IDENTIFIERS (CLIENT): Check did hierarchy rule """

        account = 'jdoe'
        rse = 'MOCK'
        scope = scope_name_generator()
        file = ['file_%s' % generate_uuid() for i in range(10)]
        dst = ['dst_%s' % generate_uuid() for i in range(4)]
        cnt = ['cnt_%s' % generate_uuid() for i in range(4)]

        scope_client.add_scope(account, scope)

        for i in range(10):
            replica_client.add_replica(rse, scope, file[i], 1, '0cc737eb')
        for i in range(4):
            did_client.add_did(scope, dst[i], 'DATASET', statuses=None, meta=None, rules=None)
        for i in range(4):
            did_client.add_did(scope, cnt[i], 'CONTAINER', statuses=None, meta=None, rules=None)

        for i in range(4):
            did_client.add_files_to_dataset(scope, dst[i], [{'scope': scope, 'name': file[2 * i], 'bytes': 1, 'adler32': '0cc737eb'},
                                                            {'scope': scope, 'name': file[2 * i + 1], 'bytes': 1, 'adler32': '0cc737eb'}])

        did_client.add_containers_to_container(scope, cnt[1], [{'scope': scope, 'name': cnt[2]}, {'scope': scope, 'name': cnt[3]}])
        did_client.add_datasets_to_container(scope, cnt[0], [{'scope': scope, 'name': dst[1]}, {'scope': scope, 'name': dst[2]}])

        result = did_client.scope_list(scope, recursive=True)
        for r in result:
            pass
            # TODO: fix, fix, fix
            # if r['name'] == cnt[1]:
            #    assert r['type'] == 'container'
            #    assert r['level'] == 0
            # if (r['name'] == cnt[0]) or (r['name'] == dst[0]) or (r['name'] == file[8]) or (r['name'] == file[9]):
            #    assert r['level'] == 0
            # else:
            #     assert r['level'] == 1

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_detach_did(self, did_client, replica_client, scope_client):
        """ DATA IDENTIFIERS (CLIENT): Detach dids from a did"""

        account = 'jdoe'
        rse = 'MOCK'
        scope = scope_name_generator()
        file = ['file_%s' % generate_uuid() for i in range(10)]
        dst = ['dst_%s' % generate_uuid() for i in range(5)]
        cnt = ['cnt_%s' % generate_uuid() for i in range(2)]

        scope_client.add_scope(account, scope)

        for i in range(10):
            replica_client.add_replica(rse, scope, file[i], 1, '0cc737eb')
        for i in range(5):
            did_client.add_dataset(scope, dst[i], statuses=None, meta=None, rules=None)
        for i in range(2):
            did_client.add_container(scope, cnt[i], statuses=None, meta=None, rules=None)

        for i in range(5):
            did_client.add_files_to_dataset(scope, dst[i], [{'scope': scope, 'name': file[2 * i], 'bytes': 1, 'adler32': '0cc737eb'},
                                                            {'scope': scope, 'name': file[2 * i + 1], 'bytes': 1, 'adler32': '0cc737eb'}])

        did_client.add_containers_to_container(scope, cnt[1], [{'scope': scope, 'name': dst[2]}, {'scope': scope, 'name': dst[3]}])

        with pytest.raises(UnsupportedOperation):
            did_client.add_datasets_to_container(scope, cnt[0], [{'scope': scope, 'name': dst[1]}, {'scope': scope, 'name': cnt[1]}])

        did_client.add_datasets_to_container(scope, cnt[0], [{'scope': scope, 'name': dst[1]}, {'scope': scope, 'name': dst[2]}])

        did_client.detach_dids(scope, cnt[0], [{'scope': scope, 'name': dst[1]}])
        did_client.detach_dids(scope, dst[3], [{'scope': scope, 'name': file[6]}, {'scope': scope, 'name': file[7]}])
        result = did_client.scope_list(scope, recursive=True)
        for r in result:
            if r['name'] == dst[1]:
                assert r['level'] == 0
            if r['type'] == 'file':
                if (r['name'] in file[6:9]):
                    assert r['level'] == 0
                else:
                    assert r['level'] != 0

        with pytest.raises(UnsupportedOperation):
            did_client.detach_dids(scope=scope, name=cnt[0], dids=[{'scope': scope, 'name': cnt[0]}])

        did_client.close(scope, dst[4])
        metadata = did_client.get_metadata(scope, dst[4])
        i_bytes, i_length = metadata['bytes'], metadata['length']
        metadata = did_client.get_metadata(scope, file[8])
        file1_bytes = metadata['bytes']
        metadata = did_client.get_metadata(scope, file[9])
        file2_bytes = metadata['bytes']
        did_client.detach_dids(scope, dst[4], [{'scope': scope, 'name': file[8]}, {'scope': scope, 'name': file[9]}])
        metadata = did_client.get_metadata(scope, dst[4])
        f_bytes, f_length = metadata['bytes'], metadata['length']
        assert i_bytes == f_bytes + file1_bytes + file2_bytes
        assert i_length == f_length + 1 + 1

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_scope_list(self, did_client, replica_client, rse_client, scope_client):
        """ DATA IDENTIFIERS (CLIENT): Add, aggregate, and list data identifiers in a scope """

        # create some dummy data
        tmp_accounts = ['jdoe' for i in range(3)]
        tmp_scopes = [scope_name_generator() for i in range(3)]
        tmp_rses = [rse_name_generator() for i in range(3)]
        tmp_files = ['file_%s' % generate_uuid() for i in range(3)]
        tmp_datasets = ['dataset_%s' % generate_uuid() for i in range(3)]
        tmp_containers = ['container_%s' % generate_uuid() for i in range(3)]

        # add dummy data to the catalogue
        for i in range(3):
            scope_client.add_scope(tmp_accounts[i], tmp_scopes[i])
            rse_client.add_rse(tmp_rses[i])
            replica_client.add_replica(tmp_rses[i], tmp_scopes[i], tmp_files[i], 1, '0cc737eb')

        # put files in datasets
        for i in range(3):
            for j in range(3):
                files = [{'scope': tmp_scopes[j], 'name': tmp_files[j], 'bytes': 1, 'adler32': '0cc737eb'}]
                did_client.add_dataset(tmp_scopes[i], tmp_datasets[j])
                did_client.add_files_to_dataset(tmp_scopes[i], tmp_datasets[j], files)

        # put datasets in containers
        for i in range(3):
            for j in range(3):
                datasets = [{'scope': tmp_scopes[j], 'name': tmp_datasets[j]}]
                did_client.add_container(tmp_scopes[i], tmp_containers[j])
                did_client.add_datasets_to_container(tmp_scopes[i], tmp_containers[j], datasets)

        # reverse check if everything is in order
        for i in range(3):
            result = did_client.scope_list(tmp_scopes[i], recursive=True)

            r_topdids = []
            r_otherscopedids = []
            r_scope = []
            for r in result:
                if r['level'] == 0:
                    r_topdids.append(r['scope'] + ':' + r['name'])
                    r_scope.append(r['scope'])
                if r['scope'] != tmp_scopes[i]:
                    r_otherscopedids.append(r['scope'] + ':' + r['name'])
                    assert r['level'] in [1, 2]

            for j in range(3):
                assert tmp_scopes[i] == r_scope[j]
                if j != i:
                    assert tmp_scopes[j] + ':' + tmp_files[j] in r_otherscopedids
            assert tmp_scopes[i] + ':' + tmp_files[i] not in r_topdids

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_get_did(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): add a new data identifier and try to retrieve it back"""
        rse = 'MOCK'
        scope = 'mock'
        file = generate_uuid()
        dsn = generate_uuid()

        replica_client.add_replica(rse, scope, file, 1, '0cc737eb')

        did = did_client.get_did(scope, file)

        assert did['scope'] == scope
        assert did['name'] == file

        did_client.add_dataset(scope=scope, name=dsn, lifetime=10000000)
        did2 = did_client.get_did(scope, dsn)
        assert type(did2['expired_at']) == datetime

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_get_meta(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): add a new meta data for an identifier and try to retrieve it back"""
        rse = 'MOCK'
        scope = 'mock'
        file = generate_uuid()
        keys = ['project', 'run_number']
        values = ['data13_hip', 12345678]

        replica_client.add_replica(rse, scope, file, 1, '0cc737eb')
        for i in range(2):
            did_client.set_metadata(scope, file, keys[i], values[i])

        meta = did_client.get_metadata(scope, file)

        for i in range(2):
            assert meta[keys[i]] == values[i]

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_content(self, did_client):
        """ DATA IDENTIFIERS (CLIENT): test to list contents for an identifier"""
        rse = 'MOCK'
        scope = 'mock'
        nbfiles = 5
        dataset1 = generate_uuid()
        dataset2 = generate_uuid()
        container = generate_uuid()
        files1 = [{'scope': scope, 'name': generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'} for i in range(nbfiles)]
        files2 = [{'scope': scope, 'name': generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'} for i in range(nbfiles)]

        did_client.add_dataset(scope, dataset1)

        with pytest.raises(DataIdentifierAlreadyExists):
            did_client.add_dataset(scope, dataset1)

        did_client.add_files_to_dataset(scope, dataset1, files1, rse=rse)

        did_client.add_dataset(scope, dataset2)
        did_client.add_files_to_dataset(scope, dataset2, files2, rse=rse)

        did_client.add_container(scope, container)
        datasets = [{'scope': scope, 'name': dataset1}, {'scope': scope, 'name': dataset2}]
        did_client.add_datasets_to_container(scope, container, datasets)

        contents = did_client.list_content(scope, container)

        datasets_s = [d['name'] for d in contents]
        assert dataset1 in datasets_s
        assert dataset2 in datasets_s

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_files(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): List files for a container"""
        rse = 'MOCK'
        scope = 'mock'
        dataset1 = generate_uuid()
        dataset2 = generate_uuid()
        container = generate_uuid()
        files1 = []
        files2 = []
        for i in range(10):
            files1.append({'scope': scope, 'name': generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'})
            files2.append({'scope': scope, 'name': generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'})

        for i in range(10):
            replica_client.add_replica(rse, scope, files1[i]['name'], 1, '0cc737eb')
            replica_client.add_replica(rse, scope, files2[i]['name'], 1, '0cc737eb')

        did_client.add_dataset(scope, dataset1)
        did_client.add_files_to_dataset(scope, dataset1, files1)

        did_client.add_dataset(scope, dataset2)
        did_client.add_files_to_dataset(scope, dataset2, files2)
        datasets = [{'scope': scope, 'name': dataset1}, {'scope': scope, 'name': dataset2}]
        did_client.add_container(scope, container)
        did_client.add_datasets_to_container(scope, container, datasets)

        # List file content
        content = did_client.list_files(scope, files1[i]['name'])
        assert content is not None
        for d in content:
            assert d['name'] == files1[i]['name']

        # List container content
        for d in [{'name': x['name'], 'scope': x['scope'], 'bytes': x['bytes'], 'adler32': x['adler32']} for x in did_client.list_files(scope, container)]:
            assert d in files1 + files2

        # List non-existing data identifier content
        with pytest.raises(DataIdentifierNotFound):
            did_client.list_files(scope, 'Nimportnawak')

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_replicas(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): List replicas for a container"""
        rse = 'MOCK'
        scope = 'mock'
        dsn1 = generate_uuid()
        dsn2 = generate_uuid()
        cnt = generate_uuid()
        files1 = []
        files2 = []
        for i in range(10):
            files1.append({'scope': scope, 'name': generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'})
            files2.append({'scope': scope, 'name': generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'})

        did_client.add_dataset(scope, dsn1)
        did_client.add_files_to_dataset(scope, dsn1, files1, rse=rse)

        did_client.add_dataset(scope, dsn2)
        did_client.add_files_to_dataset(scope, dsn2, files2, rse=rse)

        did_client.add_container(scope, cnt)
        did_client.add_datasets_to_container(scope, cnt, [{'scope': scope, 'name': dsn1}, {'scope': scope, 'name': dsn2}])

        replicas = replica_client.list_replicas(dids=[{'scope': scope, 'name': dsn1}])
        assert replicas is not None

        replicas = replica_client.list_replicas(dids=[{'scope': scope, 'name': cnt}])
        assert replicas is not None

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_close(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): test to close data identifiers"""

        tmp_rse = 'MOCK'
        tmp_scope = 'mock'

        # Add dataset
        tmp_dataset = 'dsn_%s' % generate_uuid()

        # Add file replica
        tmp_file = 'file_%s' % generate_uuid()
        replica_client.add_replica(rse=tmp_rse, scope=tmp_scope, name=tmp_file, bytes_=1, adler32='0cc737eb')

        # Add dataset
        did_client.add_dataset(scope=tmp_scope, name=tmp_dataset)

        # Add files to dataset
        files = [{'scope': tmp_scope, 'name': tmp_file, 'bytes': 1, 'adler32': '0cc737eb'}, ]
        did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dataset, files=files)

        # Add a second file replica
        tmp_file = 'file_%s' % generate_uuid()
        replica_client.add_replica(tmp_rse, tmp_scope, tmp_file, 1, '0cc737eb')
        # Add files to dataset
        files = [{'scope': tmp_scope, 'name': tmp_file, 'bytes': 1, 'adler32': '0cc737eb'}, ]
        did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dataset, files=files)

        # Close dataset
        with pytest.raises(UnsupportedStatus):
            did_client.set_status(scope=tmp_scope, name=tmp_dataset, close=False)
        did_client.set_status(scope=tmp_scope, name=tmp_dataset, open=False)

        # Add a third file replica
        tmp_file = 'file_%s' % generate_uuid()
        replica_client.add_replica(tmp_rse, tmp_scope, tmp_file, 1, '0cc737eb')
        # Add files to dataset
        files = [{'scope': tmp_scope, 'name': tmp_file, 'bytes': 1, 'adler32': '0cc737eb'}, ]
        with pytest.raises(exception.UnsupportedOperation):
            did_client.attach_dids(scope=tmp_scope, name=tmp_dataset, dids=files)

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_open(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): test to re-open data identifiers for priv account"""

        tmp_rse = 'MOCK'
        tmp_scope = 'mock'

        # Add dataset
        tmp_dataset = 'dsn_%s' % generate_uuid()

        # Add file replica
        tmp_file = 'file_%s' % generate_uuid()
        replica_client.add_replica(rse=tmp_rse, scope=tmp_scope, name=tmp_file, bytes_=1, adler32='0cc737eb')

        # Add dataset
        did_client.add_dataset(scope=tmp_scope, name=tmp_dataset)

        # Add files to dataset
        files = [{'scope': tmp_scope, 'name': tmp_file, 'bytes': 1, 'adler32': '0cc737eb'}, ]
        did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dataset, files=files)

        # Add a second file replica
        tmp_file = 'file_%s' % generate_uuid()
        replica_client.add_replica(tmp_rse, tmp_scope, tmp_file, 1, '0cc737eb')
        # Add files to dataset
        files = [{'scope': tmp_scope, 'name': tmp_file, 'bytes': 1, 'adler32': '0cc737eb'}, ]
        did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dataset, files=files)

        # Close dataset
        with pytest.raises(UnsupportedStatus):
            did_client.set_status(scope=tmp_scope, name=tmp_dataset, close=False)
        did_client.set_status(scope=tmp_scope, name=tmp_dataset, open=False)

        # Add a third file replica
        did_client.set_status(scope=tmp_scope, name=tmp_dataset, open=True)

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_bulk_get_meta(self, did_client, replica_client):
        """ DATA IDENTIFIERS (CLIENT): Add a new meta data for a list of DIDs and try to retrieve them back"""
        key = 'project'
        rse = 'MOCK'
        scope = 'mock'
        files = ['file_%s' % generate_uuid() for _ in range(4)]
        dst = ['dst_%s' % generate_uuid() for _ in range(4)]
        cnt = ['cnt_%s' % generate_uuid() for _ in range(4)]
        meta_mapping = {}
        list_dids = []

        # Set file metadata
        for idx in range(4):
            replica_client.add_replica(rse, scope, files[idx], 1, '0cc737eb')
            did_client.set_metadata(scope, files[idx], key, 'file_%s' % idx)
            list_dids.append({'scope': scope, 'name': files[idx]})
            meta_mapping['%s:%s' % (scope, files[idx])] = (key, 'file_%s' % idx)

        # Set dataset metadata
        for idx in range(4):
            did_client.add_did(scope, dst[idx], 'DATASET', statuses=None, meta={key: 'dsn_%s' % idx}, rules=None)
            list_dids.append({'scope': scope, 'name': dst[idx]})
            meta_mapping['%s:%s' % (scope, dst[idx])] = (key, 'dsn_%s' % idx)

        # Set container metadata
        for idx in range(4):
            did_client.add_did(scope, cnt[idx], 'CONTAINER', statuses=None, meta={key: 'cnt_%s' % idx}, rules=None)
            list_dids.append({'scope': scope, 'name': cnt[idx]})
            meta_mapping['%s:%s' % (scope, cnt[idx])] = (key, 'cnt_%s' % idx)
        # List metadata using the bulk method
        list_meta = [_ for _ in did_client.get_metadata_bulk(list_dids)]
        res_list_dids = [{'scope': entry['scope'], 'name': entry['name']} for entry in list_meta]
        res_list_dids.sort(key=lambda item: item['name'])
        list_dids.sort(key=lambda item: item['name'])
        assert list_dids == res_list_dids
        for meta in list_meta:
            did = '%s:%s' % (meta['scope'], meta['name'])
            met = meta_mapping[did]
            assert (key, meta[key]) == met

        # Create new containers without metadata
        cnt = ['cnt_%s' % generate_uuid() for _ in range(4)]
        for idx in range(4):
            list_dids.append({'scope': scope, 'name': cnt[idx]})
        list_meta = [_ for _ in did_client.get_metadata_bulk(list_dids)]
        assert len(list_meta) == 12
        list_dids = []
        for idx in range(4):
            list_dids.append({'scope': scope, 'name': cnt[idx]})
        list_meta = [_ for _ in did_client.get_metadata_bulk(list_dids)]
        assert len(list_meta) == 0


@pytest.mark.noparallel(reason='uses mock scope')
def test_bulk_get_meta_inheritance(vo, rse_factory, mock_scope, did_factory, rucio_client):
    """ DATA IDENTIFIERS (CLIENT): Add metadata for a hierarchical list of DIDs and check that the metadata are inherited"""
    skip_without_json()
    key = 'generic_metadata'
    nb_dids = 4
    scope = mock_scope.external
    rse, _ = rse_factory.make_posix_rse()
    meta_mapping = {}
    list_dids = []

    files = [did_factory.upload_test_file(rse) for _ in range(nb_dids)]
    datasets = [did_factory.make_dataset() for _ in range(nb_dids)]
    containers = [did_factory.make_container() for _ in range(nb_dids)]

    # Set the files metadata
    for idx, file_ in enumerate(files):
        fkey = 'file_%s' % key
        rucio_client.set_metadata(scope, file_['name'], fkey, 'file_%s' % idx)
        list_dids.append({'scope': scope, 'name': file_['name']})
        meta_mapping['%s:%s' % (scope, file_['name'])] = {fkey: 'file_%s' % idx}

    # Set the datasets metadata
    for idx, dataset in enumerate(datasets):
        dkey = 'dst_%s' % key
        rucio_client.set_metadata(scope, dataset['name'], dkey, 'dsn_%s' % idx)
        rucio_client.attach_dids_to_dids([{'scope': scope, 'name': dataset['name'], 'dids': [{'scope': scope, 'name': files[idx]['name']}]}])
        meta_mapping['%s:%s' % (scope, files[idx]['name'])][dkey] = 'dsn_%s' % idx

    # Set the containers metadata
    for idx, container in enumerate(containers):
        ckey = 'cnt_%s' % key
        rucio_client.set_metadata(scope, container['name'], ckey, 'cnt_%s' % idx)
        rucio_client.attach_dids_to_dids([{'scope': scope, 'name': container['name'], 'dids': [{'scope': scope, 'name': datasets[idx]['name']}]}])
        meta_mapping['%s:%s' % (scope, files[idx]['name'])][ckey] = 'cnt_%s' % idx

    list_meta = [meta for meta in rucio_client.get_metadata_bulk(list_dids, inherit=True)]

    for meta in list_meta:
        did = '%s:%s' % (meta['scope'], meta['name'])
        met = meta_mapping[did]
        for key in met:
            assert met[key] == meta[key]


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined scope')
def test_list_by_length(vo, root_account, rse_factory, mock_scope, did_factory, did_client):
    """ DATA IDENTIFIERS (CLIENT): List did with length """

    tmp_scope = scope_name_generator()
    scope.add_scope(tmp_scope, 'root', 'root', vo)
    rse, rse_id = rse_factory.make_posix_rse()
    dataset = did_factory.upload_test_dataset(rse, tmp_scope)
    set_status(InternalScope(tmp_scope, vo), dataset[0]['dataset_name'], open=False)

    dids = did_client.list_dids(tmp_scope, {'length.gt': 0})
    results = []
    for d in dids:
        results.append(d)
    print(results)
    assert len(results) != 0

    dids = did_client.list_dids(tmp_scope, {'length.gt': -1, 'length.lt': 1})
    results = []
    for d in dids:
        results.append(d)
    assert len(results) == 0

    dids = did_client.list_dids(tmp_scope, {'length': 0})
    results = []
    for d in dids:
        results.append(d)
    assert len(results) == 0
