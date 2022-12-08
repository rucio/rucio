#!/usr/bin/env python3
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

from datetime import datetime, timedelta
from os import remove
from time import sleep

import pytest

from rucio.core.replica import (update_replica_state, list_replicas, list_bad_replicas_status)
from rucio.core.rse import add_rse_attribute
from rucio.core.did import set_metadata
from rucio.core import rse_expression_parser
from rucio.daemons.replicarecoverer.suspicious_replica_recoverer import run, stop
from rucio.db.sqla.constants import DIDType, BadFilesStatus, ReplicaState
from rucio.tests.common import execute


class TestReplicaRecoverer:

    @pytest.fixture(autouse=True)
    def setup_obj(self, vo, rse_factory, replica_client, mock_scope, file_factory):

        # Using two test RSEs
        self.rse4suspicious, self.rse4suspicious_id = rse_factory.make_posix_rse(deterministic=True, vo=vo)
        self.rse4recovery, self.rse4recovery_id = rse_factory.make_posix_rse(deterministic=True, vo=vo)

        # For testing, we create 5 files and upload them to Rucio to two test RSEs.
        self.tmp_file1 = file_factory.file_generator()
        self.tmp_file2 = file_factory.file_generator()
        self.tmp_file3 = file_factory.file_generator()
        self.tmp_file4 = file_factory.file_generator()
        self.tmp_file5 = file_factory.file_generator()

        self.listdids = [{'scope': mock_scope, 'name': f.name, 'type': DIDType.FILE}
                         for f in [self.tmp_file1, self.tmp_file2, self.tmp_file3, self.tmp_file4, self.tmp_file5]]

        for rse in [self.rse4suspicious, self.rse4recovery]:
            cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4} {5} {6}'.format(rse, mock_scope.external, self.tmp_file1, self.tmp_file2, self.tmp_file3, self.tmp_file4, self.tmp_file5)
            exitcode, out, err = execute(cmd)

            print(exitcode, out, err)
            # checking if Rucio upload went OK
            assert exitcode == 0

        # Set fictional datatypes
        set_metadata(mock_scope, self.tmp_file4.name, 'datatype', 'testtypedeclarebad')
        set_metadata(mock_scope, self.tmp_file5.name, 'datatype', 'testtypenopolicy')

        # Allow for the RSEs to be affected by the suspicious file recovery daemon
        add_rse_attribute(self.rse4suspicious_id, "enable_suspicious_file_recovery", True)
        add_rse_attribute(self.rse4recovery_id, "enable_suspicious_file_recovery", True)

        # removing physical files from /tmp location - keeping only their DB info
        remove(self.tmp_file1)
        remove(self.tmp_file2)
        remove(self.tmp_file3)
        remove(self.tmp_file4)
        remove(self.tmp_file5)

        # Reset the cache to include the new RSEs
        rse_expression_parser.REGION.invalidate()

        # Gather replica info
        replicalist = list_replicas(dids=self.listdids)

        # Changing the replica statuses as follows:
        # ----------------------------------------------------------------------------------------------------------------------------------
        # Name         State(s) declared on rse4recovery       State(s) declared on rse4suspicious        Metadata "datatype"
        # ----------------------------------------------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious (available)
        # tmp_file2    available                                suspicious + bad (unavailable)
        # tmp_file3    unavailable                              suspicious (available)                      RAW
        # tmp_file4    unavailable                              suspicious (unavailable)                    testtypedeclarebad
        # tmp_file5    unavailable                              suspicious (available)                      testtypenopolicy
        # ----------------------------------------------------------------------------------------------------------------------------------

        for replica in replicalist:
            suspicious_pfns = replica['rses'][self.rse4suspicious_id]
            #  Declare each file as suspicious multiple times, except for tmp_file6
            for i in range(3):
                print("Declaring suspicious file replica: " + suspicious_pfns[0])
                # The reason must contain the word "checksum", so that the replica can be declared bad.
                replica_client.declare_suspicious_file_replicas([suspicious_pfns[0], ], 'checksum')
                sleep(1)
            if replica['name'] == self.tmp_file2.name:
                print("Declaring bad file replica: " + suspicious_pfns[0])
                replica_client.declare_bad_file_replicas([suspicious_pfns[0], ], 'checksum')
            if replica['name'] == self.tmp_file3.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, mock_scope, self.tmp_file3.name, ReplicaState.UNAVAILABLE)
            if replica['name'] == self.tmp_file4.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, mock_scope, self.tmp_file4.name, ReplicaState.UNAVAILABLE)
            if replica['name'] == self.tmp_file5.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, mock_scope, self.tmp_file5.name, ReplicaState.UNAVAILABLE)

        # Gather replica info after setting initial replica statuses
        replicalist = list_replicas(dids=self.listdids)

        # Checking if the status changes were effective
        for replica in replicalist:
            if replica['name'] == self.tmp_file1.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == self.tmp_file2.name:
                assert (self.rse4suspicious_id in replica['states']) is False
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == self.tmp_file3.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file4.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file5.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        # Checking if self.tmp_file2 and self.tmp_file6 were declared as 'BAD'
        self.from_date = datetime.utcnow() - timedelta(days=1)
        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4suspicious_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file2.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file3.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file5.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist

        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4recovery_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file2.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file3.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file5.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist

        # On purpose not checking for status to be declared 'SUSPICIOUS' on rse4suspicious.
        # The only existing function (to date) gathering info about 'SUSPICIOUS' replicas
        # is used (currently only) from the tested replica_recoverer itself.

    def test_replica_recoverer(self, vo):
        """ REPLICA RECOVERER: Testing declaration of suspicious replicas as bad if they are found available on other RSEs.

            setUp function (above) is supposed to run first
            (nose does this automatically):

            - uploads 6 test files to two test RSEs (rse4recovery, rse4suspicious)
            - prepares their statuses to be as follows:

            # ----------------------------------------------------------------------------------------------------------------------------------
            # Name         State(s) declared on rse4recovery       State(s) declared on rse4suspicious        Metadata "datatype"
            # ----------------------------------------------------------------------------------------------------------------------------------
            # tmp_file1    available                                suspicious (unavailable)
            # tmp_file2    available                                suspicious + bad (unavailable)
            # tmp_file3    unavailable                              suspicious (available)                      RAW
            # tmp_file4    unavailable                              suspicious (available)                      testtypedeclarebad
            # tmp_file5    unavailable                              suspicious (available)                      testtypenopolicy
            # ----------------------------------------------------------------------------------------------------------------------------------

            - Explaination: Suspicious replicas that are the last remaining copy (unavailable on rse4recovery) are handeled differently depending
                            by their metadata "datatype". RAW files have the poilcy to be ignored. testtype_declare_bad files are of a fictional
                            type that has the policy of being declared bad. testtype_nopolicy files are of a fictional type that doesn't have a
                            policy specified, meaning they should be ignored by default.

            Runs the Test:

            - running suspicious_replica_recoverer

            Concluding:

            - checks that tmp_file1, tmp_file4 and tmp_file6 were declared as 'BAD' on rse4suspicious

        """

        try:
            run(once=True, younger_than=1, nattempts=2, limit_suspicious_files_on_rse=5, sleep_time=0, active_mode=True)
        except KeyboardInterrupt:
            stop()

        # Checking the outcome:
        # We expect to see three changes: tmp_file1 and tmp_file4 should be declared as bad on rse4suspicious
        # ----------------------------------------------------------------------------------------------------------------------------------
        # Name         State(s) declared on rse4recovery       State(s) declared on rse4suspicious        Metadata "datatype"
        # ----------------------------------------------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious + bad (unavailable)
        # tmp_file2    available                                suspicious + bad (unavailable)
        # tmp_file3    unavailable                              suspicious (available)                      RAW
        # tmp_file4    unavailable                              suspicious + bad (unavailable)              testtypedeclarebad
        # tmp_file5    unavailable                              suspicious (available)                      testtypenopolicy
        # ----------------------------------------------------------------------------------------------------------------------------------

        # Gather replica info after replica_recoverer has run.
        replicalist = list_replicas(dids=self.listdids)

        for replica in replicalist:
            if replica['name'] == self.tmp_file1.name or replica['name'] == self.tmp_file2.name:
                assert (self.rse4suspicious_id in replica['states']) is False
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == self.tmp_file3.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file4.name:
                # The 'states' should be empty if the replica isn't available on at least one RSE
                assert not replica.get('states')
            if replica['name'] == self.tmp_file5.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        # Checking if replicas were declared as 'BAD'
        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4suspicious_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file2.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file3.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file5.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist

        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4recovery_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file2.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file3.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file5.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
