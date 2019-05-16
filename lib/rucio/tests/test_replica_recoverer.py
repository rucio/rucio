# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019

from __future__ import print_function
from os import remove, path
from time import sleep
from datetime import datetime, timedelta

from nose.tools import assert_true

from rucio.core.replica import (update_replica_state, list_replicas, list_bad_replicas_status)
from rucio.client.replicaclient import ReplicaClient
from rucio.db.sqla.constants import DIDType, BadFilesStatus, ReplicaState

from rucio.tests.common import execute, file_generator
from rucio.daemons.replicarecoverer.suspicious_replica_recoverer import run, stop


class TestReplicaRecoverer():

    def setUp(self):

        self.replica_client = ReplicaClient()

        # Using two test RSEs
        self.rse4suspicious = 'MOCK_SUSPICIOUS'
        self.rse4recovery = 'MOCK_RECOVERY'
        self.scope = 'mock'

        # For testing, we create 3 files and upload them to Rucio to two test RSEs.
        self.tmp_file1 = file_generator()
        self.tmp_file2 = file_generator()
        self.tmp_file3 = file_generator()

        self.listdids = [{'scope': self.scope, 'name': path.basename(self.tmp_file1), 'type': DIDType.FILE},
                         {'scope': self.scope, 'name': path.basename(self.tmp_file2), 'type': DIDType.FILE},
                         {'scope': self.scope, 'name': path.basename(self.tmp_file3), 'type': DIDType.FILE}]

        for rse in [self.rse4suspicious, self.rse4recovery]:
            cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4}'.format(rse, self.scope, self.tmp_file1, self.tmp_file2, self.tmp_file3)
            exitcode, out, err = execute(cmd)

            # checking if Rucio upload went OK
            assert_true(exitcode == 0)

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
            for i in range(3):
                print("Declaring suspicious file replica: " + replica['rses'][self.rse4suspicious][0])
                self.replica_client.declare_suspicious_file_replicas([replica['rses'][self.rse4suspicious][0], ], 'This is a good reason.')
                sleep(1)
            if replica['name'] == path.basename(self.tmp_file2):
                print("Declaring bad file replica: " + replica['rses'][self.rse4suspicious][0])
                self.replica_client.declare_bad_file_replicas([replica['rses'][self.rse4suspicious][0], ], 'This is a good reason')
            if replica['name'] == path.basename(self.tmp_file3):
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery][0])
                update_replica_state(self.rse4recovery, self.scope, path.basename(self.tmp_file3), ReplicaState.UNAVAILABLE)

        # Gather replica info after setting initial replica statuses
        replicalist = list_replicas(dids=self.listdids)

        # Checking if the status changes were effective
        for replica in replicalist:
            if replica['name'] == path.basename(self.tmp_file1):
                assert_true(replica['states'][self.rse4suspicious] == 'AVAILABLE')
                assert_true(replica['states'][self.rse4recovery] == 'AVAILABLE')
            if replica['name'] == path.basename(self.tmp_file2):
                assert_true((self.rse4suspicious in replica['states']) is False)
                assert_true(replica['states'][self.rse4recovery] == 'AVAILABLE')
            if replica['name'] == path.basename(self.tmp_file3):
                assert_true(replica['states'][self.rse4suspicious] == 'AVAILABLE')
                assert_true((self.rse4recovery in replica['states']) is False)

        # Checking if only self.tmp_file2 is declared as 'BAD'
        self.from_date = datetime.now() - timedelta(days=1)
        bad_replicas_list = list_bad_replicas_status(rse=self.rse4suspicious, younger_than=self.from_date)
        bad_checklist = [(badf['name'], badf['rse'], badf['state']) for badf in bad_replicas_list]

        assert_true((path.basename(self.tmp_file2), self.rse4suspicious, BadFilesStatus.BAD) in bad_checklist)
        assert_true((path.basename(self.tmp_file1), self.rse4suspicious, BadFilesStatus.BAD) not in bad_checklist)
        assert_true((path.basename(self.tmp_file3), self.rse4suspicious, BadFilesStatus.BAD) not in bad_checklist)

        bad_replicas_list = list_bad_replicas_status(rse=self.rse4recovery, younger_than=self.from_date)
        bad_checklist = [(badf['name'], badf['rse'], badf['state']) for badf in bad_replicas_list]

        assert_true((path.basename(self.tmp_file1), self.rse4recovery, BadFilesStatus.BAD) not in bad_checklist)
        assert_true((path.basename(self.tmp_file2), self.rse4recovery, BadFilesStatus.BAD) not in bad_checklist)
        assert_true((path.basename(self.tmp_file3), self.rse4recovery, BadFilesStatus.BAD) not in bad_checklist)

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
                assert_true((self.rse4suspicious in replica['states']) is False)
                assert_true(replica['states'][self.rse4recovery] == 'AVAILABLE')
            if replica['name'] == path.basename(self.tmp_file3):
                assert_true(replica['states'][self.rse4suspicious] == 'AVAILABLE')
                assert_true((self.rse4recovery in replica['states']) is False)

        # Checking if replicas declared as 'BAD'
        bad_replicas_list = list_bad_replicas_status(rse=self.rse4suspicious, younger_than=self.from_date)
        bad_checklist = [(badf['name'], badf['rse'], badf['state']) for badf in bad_replicas_list]

        assert_true((path.basename(self.tmp_file1), self.rse4suspicious, BadFilesStatus.BAD) in bad_checklist)
        assert_true((path.basename(self.tmp_file2), self.rse4suspicious, BadFilesStatus.BAD) in bad_checklist)
        assert_true((path.basename(self.tmp_file3), self.rse4suspicious, BadFilesStatus.BAD) not in bad_checklist)

        bad_replicas_list = list_bad_replicas_status(rse=self.rse4recovery, younger_than=self.from_date)
        bad_checklist = [(badf['name'], badf['rse'], badf['state']) for badf in bad_replicas_list]

        assert_true((path.basename(self.tmp_file1), self.rse4recovery, BadFilesStatus.BAD) not in bad_checklist)
        assert_true((path.basename(self.tmp_file2), self.rse4recovery, BadFilesStatus.BAD) not in bad_checklist)
        assert_true((path.basename(self.tmp_file3), self.rse4recovery, BadFilesStatus.BAD) not in bad_checklist)
