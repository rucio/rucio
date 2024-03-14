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
from os import remove
from os.path import basename
import time
import unittest

from rucio.api.account import add_account, add_account_attribute, del_account
from rucio.api.scope import add_scope
from rucio.common.config import config_set
from rucio.common.exception import AccessDenied
import rucio.common.test_rucio_server as server_test
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid, execute
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.daemons.conveyor.finisher import finisher
from rucio.daemons.conveyor.poller import poller
from rucio.daemons.conveyor.submitter import submitter
from rucio.db.sqla.constants import ReplicaState
from rucio.tests.common import account_name_generator, skip_non_dune
from tests.ruciopytest import NoParallelGroups


MAX_POLL_WAIT_SECONDS = 100


# Connects to the test MetaCat container and logs in
def get_metacat_client():
    from metacat.webapi import MetaCatClient
    metacat_client = MetaCatClient("http://dev_metacat_1:8080/")
    metacat_client.login_password("admin", "admin")
    return metacat_client


@pytest.mark.noparallel(reason='uses pre-defined RSE')
@skip_non_dune
class TestDUNEPolicyPackage(unittest.TestCase):
    def setUp(self):
        self.marker = '$ >'
        self.scope, self.rses = server_test.get_scope_and_rses()
        self.rse = self.rses[0]
        self.generated_file_dids = []
        self.generated_dataset_dids = []

    def tearDown(self):
        metacat_client = get_metacat_client()
        for did in self.generated_file_dids:
            server_test.delete_rules(did)
            metacat_client.delete_file(did=did)
        for did in self.generated_dataset_dids:
            server_test.delete_rules(did)
            # Ideally should also remove from MetaCat here, but remove_dataset
            # doesn't appear to actually work
            #metacat_client.remove_dataset(did)
        self.generated_file_dids = []
        self.generated_dataset_dids = []

    def test_dataset_permissions(self):
        """DUNE(PERMISSION): rucio upload dataset with and without MetaCat entries"""
        if self.rse is None:
            return

        tmp_file1 = server_test.file_generator()
        tmp_file2 = server_test.file_generator()
        tmp_file3 = server_test.file_generator()
        tmp_dsn1 = 'tests.dune_permission_dataset_' + uuid()
        tmp_dsn2 = 'tests.dune_permission_dataset_' + uuid()

        # Add files to MetaCat, but to wrong dataset
        metacat_client = get_metacat_client()
        dataset_did2 = self.scope + ":" + tmp_dsn2
        metacat_client.create_dataset(dataset_did2)
        file_did1 = self.scope + ":" + basename(tmp_file1)
        file_did2 = self.scope + ":" + basename(tmp_file2)
        file_did3 = self.scope + ":" + basename(tmp_file3)
        metacat_client.declare_file(did=file_did1, dataset_did=dataset_did2)
        metacat_client.declare_file(did=file_did2, dataset_did=dataset_did2)
        metacat_client.declare_file(did=file_did3, dataset_did=dataset_did2)

        # Adding files to dataset where dataset does not exist in MetaCat
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {1}:{5}'.format(self.rse, self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertFalse(exitcode == 0)  # should fail due to missing dataset entry

        # Now add files to correct dataset
        dataset_did1 = self.scope + ":" + tmp_dsn1
        metacat_client.create_dataset(dataset_did1)
        metacat_client.add_files(dataset_did1, file_list=[{"did": file_did1}, {"did": file_did2}, {"did": file_did3}])

        # Try uploading again
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {1}:{5}'.format(self.rse, self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        self.assertEqual(exitcode, 0)  # should succeed this time

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_dsn1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_dsn1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1}'.format(self.scope, tmp_dsn1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn1) + basename(tmp_file1))
        remove('/tmp/{0}/'.format(tmp_dsn1) + basename(tmp_file2))
        remove('/tmp/{0}/'.format(tmp_dsn1) + basename(tmp_file3))        
        self.generated_file_dids += [ file_did1, file_did2, file_did3 ]
        self.generated_dataset_dids += [ dataset_did1, dataset_did2 ]

    @pytest.mark.xfail(reason="permission check is bypassed when creating file DIDs due to Rucio bug")
    def test_file_permissions(self):
        """DUNE(PERMISSION): rucio upload files with and without MetaCat entries"""
        if self.rse is None:
            return

        tmp_file1 = server_test.file_generator()
        tmp_file2 = server_test.file_generator()
        tmp_file3 = server_test.file_generator()
        tmp_dsn = 'tests.dune_permission_dataset_' + uuid()

        # Add dataset to MetaCat, but not files yet
        metacat_client = get_metacat_client()
        dataset_did1 = self.scope + ":" + tmp_dsn
        metacat_client.create_dataset(dataset_did1)

        # Adding files to dataset where dataset does not exist in MetaCat
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {1}:{5}'.format(self.rse, self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertFalse(exitcode == 0)  # should fail due to missing file entries

        # Now add files to MetaCat as well
        file_did1 = self.scope + ":" + basename(tmp_file1)
        file_did2 = self.scope + ":" + basename(tmp_file2)
        file_did3 = self.scope + ":" + basename(tmp_file3)
        metacat_client.declare_file(did=file_did1, dataset_did=dataset_did1)
        metacat_client.declare_file(did=file_did2, dataset_did=dataset_did1)
        metacat_client.declare_file(did=file_did3, dataset_did=dataset_did1)

        # Try uploading again
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {1}:{5}'.format(self.rse, self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        self.assertEqual(exitcode, 0)  # should succeed this time

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn) + basename(tmp_file1))
        remove('/tmp/{0}/'.format(tmp_dsn) + basename(tmp_file2))
        remove('/tmp/{0}/'.format(tmp_dsn) + basename(tmp_file3))        
        self.generated_file_dids += [ file_did1, file_did2, file_did3 ]
        self.generated_dataset_dids += [ dataset_did1 ]

    def test_special_permission(self):
        """DUNE(PERMISSION): check that special DUNE permission attribute works as intended"""
        # create a Rucio account
        username = account_name_generator()
        add_account(username, 'USER', 'rucio@email.com', 'root')

        # verify that it doesn't have permission to add scope
        self.assertRaises(AccessDenied, add_scope, 'dunepermissiontest', username, username)

        # now give the account the special DUNE attribute
        add_account_attribute('add_scope', 'True', username, 'root')

        # should now be able to add scope
        add_scope('dunepermissiontest', username, username)

        # clean up the account
        del_account(username, 'root')
        
    def test_dune_lfn2pfn(self):
        """DUNE(LFN2PFN): test the DUNE lfn2pfn algorithm"""
        # get the LFN2PFN function from the policy package
        from DUNERucioPolicy import get_algorithms
        algorithms = get_algorithms()
        self.assertTrue('lfn2pfn' in algorithms)
        self.assertTrue('DUNE' in algorithms['lfn2pfn'])
        lfn2pfn_fn = algorithms['lfn2pfn']['DUNE']

        # generate a test file and test data set name
        tmp_file1 = server_test.file_generator()
        tmp_dsn1 = 'tests.dune_lfn2pfn_dataset_' + uuid()

        # declare file and dataset to MetaCat, including metadata
        metacat_client = get_metacat_client()
        dataset_did1 = self.scope + ':' + tmp_dsn1
        metacat_client.create_dataset(dataset_did1)
        metadata = {
            'core.start_time': 1709562644.0,
            'core.runs': [ 12345678 ],
            'core.run_type': 'testrun',
            'core.data_tier': 'testtier',
            'core.file_type': 'randombytes',
            'core.data_stream': 'teststream',
            'DUNE.campaign': 'votests'
        }
        file_did1 = self.scope + ':' + basename(tmp_file1)
        metacat_client.declare_file(did=file_did1, dataset_did=dataset_did1,
                                    metadata=metadata)

        # get PFN for this file
        pfn = lfn2pfn_fn(self.scope, basename(tmp_file1), self.rse, {}, {})

        # check it's as expected
        self.assertEqual(pfn, "testrun/testtier/2024/randombytes/teststream/votests/12/34/56/78/" + basename(tmp_file1))

        # remove file from MetaCat
        metacat_client.delete_file(did=file_did1)

    def test_dune_surl(self):
        """DUNE(SURL): test the DUNE SURL algorithm"""
        # get the SURL function from the policy package
        from DUNERucioPolicy import get_algorithms
        algorithms = get_algorithms()
        self.assertTrue('surl' in algorithms)
        self.assertTrue('DUNE_metacat' in algorithms['surl'])
        surl_fn = algorithms['surl']['DUNE_metacat']

        # generate a test file and test data set name
        tmp_file1 = server_test.file_generator()
        tmp_dsn1 = 'tests.dune_surl_dataset_' + uuid()

        # declare file and dataset to MetaCat, including metadata
        metacat_client = get_metacat_client()
        dataset_did1 = self.scope + ':' + tmp_dsn1
        metacat_client.create_dataset(dataset_did1)
        metadata = {
            'core.start_time': 1709562644.0,
            'core.runs': [ 12345678 ],
            'core.run_type': 'testrun',
            'core.data_tier': 'testtier',
            'core.file_type': 'randombytes',
            'core.data_stream': 'teststream',
            'DUNE.campaign': 'votests'
        }
        file_did1 = self.scope + ':' + basename(tmp_file1)
        metacat_client.declare_file(did=file_did1, dataset_did=dataset_did1,
                                    metadata=metadata)

        # get PFN for this file
        pfn = surl_fn(tmp_dsn1, self.scope, basename(tmp_file1))

        # check it's as expected
        self.assertEqual(pfn, "testrun/testtier/2024/randombytes/teststream/votests/12/34/56/78/" + basename(tmp_file1))

        # remove file from MetaCat
        metacat_client.delete_file(did=file_did1)


@skip_non_dune
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
def test_dune_replicate():
    """DUNE(REPLICATE): test uploading and replicating a file"""
    # generate test file and test dataset name
    tmp_file1 = server_test.file_generator()
    tmp_dsn1 = 'tests.dune_replicate_dataset_' + uuid()
    scope, rses = server_test.get_scope_and_rses()

    src_rse = 'XRD3'
    src_rse_id = rse_core.get_rse_id(rse=src_rse)
    dst_rse = 'XRD4'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse)
    
    # add file and dataset metadata to MetaCat
    metacat_client = get_metacat_client()
    dataset_did1 = scope + ':' + tmp_dsn1
    metacat_client.create_dataset(dataset_did1)
    metadata = {
        'core.start_time': 1709562644.0,
        'core.runs': [ 12345678 ],
        'core.run_type': 'testrun',
        'core.data_tier': 'testtier',
        'core.file_type': 'randombytes',
        'core.data_stream': 'teststream',
        'DUNE.campaign': 'votests'
    }
    file_did1 = scope + ':' + basename(tmp_file1)
    metacat_client.declare_file(did=file_did1, dataset_did=dataset_did1,
                                metadata=metadata)

    # upload file to XRD3
    cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(src_rse, scope, tmp_file1, tmp_dsn1)
    print('$ >' + cmd)
    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    assert exitcode == 0

    # set XRD4 to non-deterministic
    rse_core.update_rse(rse_id=dst_rse_id, parameters={'deterministic': False})

    try:
        # set XRD4's naming convention to DUNE
        rse_core.add_rse_attribute(dst_rse_id, "naming_convention", "DUNE_metacat")
    
        # add rule to replicate dataset to XRD4
        root_account = InternalAccount('root')
        rule_core.add_rule(dids=[{'scope': InternalScope(scope), 'name': basename(tmp_file1)}], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        
        # invoke daemons and wait for file to replicate
        submitter(once=True, rses=[{'id': src_rse_id}, {'id': dst_rse_id}], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)
        replica = {}
        for _ in range(MAX_POLL_WAIT_SECONDS):
            poller(once=True, older_than=0, partition_wait_time=0, transfertool=None)
            finisher(once=True, partition_wait_time = 0)
            replica = replica_core.get_replica(rse_id=dst_rse_id, scope=InternalScope(scope), name=basename(tmp_file1))
            if replica['state'] != ReplicaState.COPYING:
                break
            time.sleep(1)
        assert replica['state'] == ReplicaState.AVAILABLE

        # check that both replicas exist and have the expected DUNE-style PFN
        expected_pfn = "testrun/testtier/2024/randombytes/teststream/votests/12/34/56/78/" + basename(tmp_file1)
        replicas = replica_core.list_replicas(dids=[{'scope': InternalScope('test'), 'name': basename(tmp_file1)}])
        for replica in replicas:
            assert 'rses' in replica
            assert src_rse_id in replica['rses']
            assert dst_rse_id in replica['rses']
            assert replica['rses'][src_rse_id][0].endswith(expected_pfn)
            assert replica['rses'][dst_rse_id][0].endswith(expected_pfn)
        
        # clean up
        server_test.delete_rules(file_did1)
        server_test.delete_rules(dataset_did1)
        metacat_client.delete_file(did=file_did1)
        remove(tmp_file1)
    finally:
        # set XRD4 back to deterministic
        rse_core.update_rse(rse_id=dst_rse_id, parameters={'deterministic': True})
