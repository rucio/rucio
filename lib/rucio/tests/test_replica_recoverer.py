# -*- coding: utf-8 -*-
# Copyright 2019-2021 CERN
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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from __future__ import print_function

import unittest
from datetime import datetime, timedelta
from os import remove, path
from time import sleep

import pytest

from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalScope
from rucio.core.replica import (update_replica_state, list_replicas, list_bad_replicas_status)
from rucio.core.rse import get_rse_id
from rucio.daemons.replicarecoverer.suspicious_replica_recoverer import run, stop
from rucio.db.sqla.constants import DIDType, BadFilesStatus, ReplicaState
from rucio.tests.common import execute, file_generator


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestReplicaRecoverer(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        self.replica_client = ReplicaClient()

        # Using two test RSEs
        self.rse4suspicious = 'MOCK_SUSPICIOUS'
        self.rse4suspicious_id = get_rse_id(self.rse4suspicious, **self.vo)
        self.rse4recovery = 'MOCK_RECOVERY'
        self.rse4recovery_id = get_rse_id(self.rse4recovery, **self.vo)
        self.scope = 'mock'
        self.internal_scope = InternalScope(self.scope, **self.vo)

        # For testing, we create 3 files and upload them to Rucio to two test RSEs.
        self.tmp_file1 = file_generator()
        self.tmp_file2 = file_generator()
        self.tmp_file3 = file_generator()

        self.listdids = [{'scope': self.internal_scope, 'name': path.basename(f), 'type': DIDType.FILE}
                         for f in [self.tmp_file1, self.tmp_file2, self.tmp_file3]]

        for rse in [self.rse4suspicious, self.rse4recovery]:
            cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4}'.format(rse, self.scope, self.tmp_file1, self.tmp_file2, self.tmp_file3)
            exitcode, out, err = execute(cmd)

            # checking if Rucio upload went OK
            assert exitcode == 0

        # removing physical files from /tmp location - keeping only their DB info
        remove(self.tmp_file1)
        remove(self.tmp_file2)
        remove(self.tmp_file3)

        # Gather replica info
        replicalist = list_replicas(dids=self.listdids)

        # Changing the replica statuses as follows:
        # --------------------------------------------------------------------------------------------
        # Name         State(s) declared on MOCK_RECOVERY       State(s) declared on MOCK_SUSPICIOUS
        # --------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious (available)
        # tmp_file2    available                                suspicious + bad (unavailable)
        # tmp_file3    unavailable                              suspicious (available)
        # --------------------------------------------------------------------------------------------

        for replica in replicalist:
            suspicious_pfns = replica['rses'][self.rse4suspicious_id]
            for i in range(3):
                print("Declaring suspicious file replica: " + suspicious_pfns[0])
                self.replica_client.declare_suspicious_file_replicas([suspicious_pfns[0], ], 'This is a good reason.')
                sleep(1)
            if replica['name'] == path.basename(self.tmp_file2):
                print("Declaring bad file replica: " + suspicious_pfns[0])
                self.replica_client.declare_bad_file_replicas([suspicious_pfns[0], ], 'This is a good reason')
            if replica['name'] == path.basename(self.tmp_file3):
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.internal_scope, path.basename(self.tmp_file3), ReplicaState.UNAVAILABLE)

        # Gather replica info after setting initial replica statuses
        replicalist = list_replicas(dids=self.listdids)

        # Checking if the status changes were effective
        for replica in replicalist:
            if replica['name'] == path.basename(self.tmp_file1):
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == path.basename(self.tmp_file2):
                assert (self.rse4suspicious_id in replica['states']) is False
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == path.basename(self.tmp_file3):
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        # Checking if only self.tmp_file2 is declared as 'BAD'
        self.from_date = datetime.now() - timedelta(days=1)
        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4suspicious_id, younger_than=self.from_date, **self.vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (path.basename(self.tmp_file2), self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (path.basename(self.tmp_file1), self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (path.basename(self.tmp_file3), self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist

        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4recovery_id, younger_than=self.from_date, **self.vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (path.basename(self.tmp_file1), self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (path.basename(self.tmp_file2), self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (path.basename(self.tmp_file3), self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist

        # On purpose not checking for status to be declared 'SUSPICIOUS' on MOCK_SUSPICIOUS.
        # The only existing function (to date) gathering info about 'SUSPICIOUS' replicas
        # is used (currently only) from the tested replica_recoverer itself.

    def test_replica_recoverer(self):
        """ REPLICA RECOVERER: Testing declaration of suspicious replicas as bad if they are found available on other RSEs.

            setUp function (above) is supposed to run first
            (nose does this automatically):

            - uploads 3 test files to two test RSEs ('MOCK_RECOVERY', 'MOCK_SUSPICIOUS')
            - prepares their statuses to be as follows:

            # --------------------------------------------------------------------------------------------
            # Name         State(s) declared on MOCK_RECOVERY       State(s) declared on MOCK_SUSPICIOUS
            # --------------------------------------------------------------------------------------------
            # tmp_file1    available                                suspicious (available)
            # tmp_file2    available                                suspicious + bad (unavailable)
            # tmp_file3    unavailable                              suspicious (available)
            # --------------------------------------------------------------------------------------------

            Runs the Test:

            - running suspicious_replica_recoverer

            Concluding:

            - checks that the only change made is that tmp_file1 was declared as 'BAD on 'MOCK_SUSPICIOUS'

        """

        # Run replica recoverer once
        try:
            run(once=True, younger_than=1, nattempts=2, rse_expression='MOCK_SUSPICIOUS')
        except KeyboardInterrupt:
            stop()

        # Checking the outcome:
        # we expect to see only one change, i.e. tmp_file1 declared as bad on MOCK_SUSPICIOUS
        # --------------------------------------------------------------------------------------------
        # Name         State(s) declared on MOCK_RECOVERY       State(s) declared on MOCK_SUSPICIOUS
        # --------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious + bad (unavailable)
        # tmp_file2    available                                suspicious + bad (unavailable)
        # tmp_file3    unavailable                              suspicious (available)
        # --------------------------------------------------------------------------------------------

        # Gather replica info after replica_recoverer has run.
        replicalist = list_replicas(dids=self.listdids)

        for replica in replicalist:
            if replica['name'] == path.basename(self.tmp_file1) or replica['name'] == path.basename(self.tmp_file2):
                assert (self.rse4suspicious_id in replica['states']) is False
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == path.basename(self.tmp_file3):
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        # Checking if replicas declared as 'BAD'
        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4suspicious_id, younger_than=self.from_date, **self.vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (path.basename(self.tmp_file1), self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (path.basename(self.tmp_file2), self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (path.basename(self.tmp_file3), self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist

        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4recovery_id, younger_than=self.from_date, **self.vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (path.basename(self.tmp_file1), self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (path.basename(self.tmp_file2), self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (path.basename(self.tmp_file3), self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
