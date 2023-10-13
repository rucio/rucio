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
import json

from rucio.core.replica import (update_replica_state, list_replicas, list_bad_replicas_status)
from rucio.core.rse import add_rse_attribute
from rucio.core.did import set_metadata
from rucio.core import rse_expression_parser
from rucio.daemons.replicarecoverer.suspicious_replica_recoverer import run, stop
from rucio.db.sqla.constants import DIDType, BadFilesStatus, ReplicaState
from rucio.tests.common import execute


class TestReplicaRecoverer:

    @pytest.fixture(autouse=True)
    def setup_obj(self, vo, rse_factory, replica_client, mock_scope, file_factory, scope_factory):

        # Using two test RSEs
        self.rse4suspicious, self.rse4suspicious_id = rse_factory.make_posix_rse(deterministic=True, vo=vo)
        self.rse4recovery, self.rse4recovery_id = rse_factory.make_posix_rse(deterministic=True, vo=vo)

        # Create new scopes
        _, [self.scope_declarebad] = scope_factory(vos=[vo])
        _, [self.scope_nopolicy] = scope_factory(vos=[vo])
        _, [self.scope_ignore] = scope_factory(vos=[vo])

        # For testing, we create 5 files and upload them to Rucio to two test RSEs.
        self.tmp_file1 = file_factory.file_generator()
        self.tmp_file2 = file_factory.file_generator()
        self.tmp_file3 = file_factory.file_generator()
        self.tmp_file4 = file_factory.file_generator()
        self.tmp_file5 = file_factory.file_generator()
        self.tmp_file6 = file_factory.file_generator()
        self.tmp_file7 = file_factory.file_generator()
        self.tmp_file8 = file_factory.file_generator()
        self.tmp_file9 = file_factory.file_generator()
        self.tmp_file10 = file_factory.file_generator()
        self.tmp_file11 = file_factory.file_generator()  # tmp_file11 shouldn't be declare as bad, as it doesn't have a data type.
        self.tmp_file12 = file_factory.file_generator()  # tmp_file12 is used to test the creation of rules by the daemon.
        self.tmp_file13 = file_factory.file_generator()

        self.listdids_mock = [{'scope': mock_scope, 'name': f.name, 'type': DIDType.FILE}
                              for f in [self.tmp_file1, self.tmp_file2, self.tmp_file3, self.tmp_file4, self.tmp_file5, self.tmp_file6, self.tmp_file12]]
        self.listdids_declarebad = [{'scope': self.scope_declarebad, 'name': f.name, 'type': DIDType.FILE}
                                    for f in [self.tmp_file7, self.tmp_file9, self.tmp_file11, self.tmp_file13]]
        self.listdids_nopolicy = [{'scope': self.scope_nopolicy, 'name': f.name, 'type': DIDType.FILE}
                                  for f in [self.tmp_file8]]
        self.listdids_ignore = [{'scope': self.scope_ignore, 'name': f.name, 'type': DIDType.FILE}
                                for f in [self.tmp_file10]]

        for rse in [self.rse4suspicious, self.rse4recovery]:
            # Upload files with scope "mock_scope"
            cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4} {5} {6} {7} {8}'.format(rse, mock_scope.external, self.tmp_file1, self.tmp_file2, self.tmp_file3, self.tmp_file4, self.tmp_file5, self.tmp_file6, self.tmp_file12)
            exitcode, out, err = execute(cmd)
            print("mock_scope:", exitcode, out, err)
            # checking if Rucio upload went OK
            assert exitcode == 0

            # Upload files with scope "scope_declarebad"
            cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(rse, self.scope_declarebad.external, self.tmp_file7, self.tmp_file9, self.tmp_file11, self.tmp_file13)
            exitcode, out, err = execute(cmd)
            print("scope_declarebad:", exitcode, out, err)
            # checking if Rucio upload went OK
            assert exitcode == 0

            # Upload files with scope "scope_nopolicy"
            cmd = 'rucio -v upload --rse {0} --scope {1} {2}'.format(rse, self.scope_nopolicy.external, self.tmp_file8)
            exitcode, out, err = execute(cmd)
            print("scope_nopolicy:", exitcode, out, err)
            # checking if Rucio upload went OK
            assert exitcode == 0

            # Upload files with scope "scope_nopolicy"
            cmd = 'rucio -v upload --rse {0} --scope {1} {2}'.format(rse, self.scope_ignore.external, self.tmp_file10)
            exitcode, out, err = execute(cmd)
            print("scope_ignore:", exitcode, out, err)
            # checking if Rucio upload went OK
            assert exitcode == 0

        # Explaination of the fictional data types:
        # testtypedeclarebad: Files are speficied to be declared bad
        # testtypeignore: Files are specified to be ignored
        # testtypenopolicy: Files either have no policy or no recognised policy and are ignored by default

        # Set fictional datatypes
        set_metadata(mock_scope, self.tmp_file3.name, 'datatype', 'RAW')
        set_metadata(mock_scope, self.tmp_file4.name, 'datatype', 'testtypedeclarebad')
        set_metadata(mock_scope, self.tmp_file5.name, 'datatype', 'testtypenopolicy')
        set_metadata(mock_scope, self.tmp_file6.name, 'datatype', 'testtypeignore')
        set_metadata(self.scope_declarebad, self.tmp_file7.name, 'datatype', 'testtypenopolicy')
        set_metadata(self.scope_nopolicy, self.tmp_file8.name, 'datatype', 'testtypenopolicy')
        set_metadata(self.scope_declarebad, self.tmp_file9.name, 'datatype', 'testtypeignore')
        set_metadata(self.scope_ignore, self.tmp_file10.name, 'datatype', 'testtypedeclarebad')
        set_metadata(self.scope_declarebad, self.tmp_file13.name, 'datatype', 'testtypedryrun')
        # tmp_file1, 2, 11 and 12 don't have a datatypes.

        # Allow for the RSEs to be affected by the suspicious file recovery daemon
        add_rse_attribute(self.rse4suspicious_id, "enable_suspicious_file_recovery", True)
        add_rse_attribute(self.rse4recovery_id, "enable_suspicious_file_recovery", True)

        # removing physical files from /tmp location - keeping only their DB info
        remove(self.tmp_file1)
        remove(self.tmp_file2)
        remove(self.tmp_file3)
        remove(self.tmp_file4)
        remove(self.tmp_file5)
        remove(self.tmp_file6)
        remove(self.tmp_file7)
        remove(self.tmp_file8)
        remove(self.tmp_file9)
        remove(self.tmp_file10)
        remove(self.tmp_file11)
        remove(self.tmp_file12)
        remove(self.tmp_file13)

        # Reset the cache to include the new RSEs
        rse_expression_parser.REGION.invalidate()

        # Gather replica info
        replicalist_scope_mock = list(list_replicas(dids=self.listdids_mock))
        replicalist_scope_declarebad = list(list_replicas(dids=self.listdids_declarebad))
        replicalist_scope_nopolicy = list(list_replicas(dids=self.listdids_nopolicy))
        replicalist_scope_ignore = list(list_replicas(dids=self.listdids_ignore))

        # Changing the replica statuses as follows:
        # ----------------------------------------------------------------------------------------------------------------------------------------------------
        # Name         State(s) declared on rse4recovery       State(s) declared on rse4suspicious        Scope                     Metadata "datatype"
        # ----------------------------------------------------------------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious (available)                    mock_scope                  <none>
        # tmp_file2    available                                suspicious + bad (unavailable)            mock_scope                  <none>
        # tmp_file3    unavailable                              suspicious (available)                    mock_scope                  RAW
        # tmp_file4    unavailable                              suspicious (available)                    mock_scope                  testtypedeclarebad
        # tmp_file5    unavailable                              suspicious (available)                    mock_scope                  testtypenopolicy
        # tmp_file6    unavailable                              suspicious (available)                    mock_scope                  testtypeignore
        # tmp_file7    unavailable                              suspicious (available)                    scope_declarebad            testtypenopolicy
        # tmp_file8    unavailable                              suspicious (available)                    scope_nopolicy              testtypenopolicy
        # tmp_file9    unavailable                              suspicious (available)                    scope_declarebad            testtypeignore
        # tmp_file10   unavailable                              suspicious (available)                    scope_ignore                testtypedeclarebad
        # tmp_file11   unavailable                              suspicious (available)                    scope_declarebad            <none>
        # tmp_file12   unavailable                              suspicious (available)                    mock_scope                  <none>
        # tmp_file13   unavailable                              suspicious (available)                    scope_declarebad            testtypedryrun
        # ----------------------------------------------------------------------------------------------------------------------------------------------------

        for replica in replicalist_scope_mock:
            suspicious_pfns = replica['rses'][self.rse4suspicious_id]
            # Declare each file as suspicious multiple times, apart from tmp_file12, which
            # should only be declared suspicious once. tmp_file12 is used to test the
            # creation of rules by the daemon.
            if replica['name'] == self.tmp_file12.name:
                print("Declaring suspicious file replica: " + suspicious_pfns[0])
                # The reason must contain the word "checksum", so that the replica can be declared bad.
                replica_client.declare_suspicious_file_replicas([suspicious_pfns[0], ], 'checksum')
                sleep(1)
            else:
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
            if replica['name'] == self.tmp_file6.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, mock_scope, self.tmp_file6.name, ReplicaState.UNAVAILABLE)
            if replica['name'] == self.tmp_file12.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, mock_scope, self.tmp_file12.name, ReplicaState.UNAVAILABLE)

        for replica in replicalist_scope_declarebad:
            suspicious_pfns = replica['rses'][self.rse4suspicious_id]
            #  Declare each file as suspicious multiple times
            for i in range(3):
                print("Declaring suspicious file replica: " + suspicious_pfns[0])
                # The reason must contain the word "checksum", so that the replica can be declared bad.
                replica_client.declare_suspicious_file_replicas([suspicious_pfns[0], ], 'checksum')
                sleep(1)
            if replica['name'] == self.tmp_file7.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.scope_declarebad, self.tmp_file7.name, ReplicaState.UNAVAILABLE)
            if replica['name'] == self.tmp_file9.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.scope_declarebad, self.tmp_file9.name, ReplicaState.UNAVAILABLE)
            if replica['name'] == self.tmp_file11.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.scope_declarebad, self.tmp_file11.name, ReplicaState.UNAVAILABLE)
            if replica['name'] == self.tmp_file13.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.scope_declarebad, self.tmp_file13.name, ReplicaState.UNAVAILABLE)

        for replica in replicalist_scope_nopolicy:
            suspicious_pfns = replica['rses'][self.rse4suspicious_id]
            #  Declare each file as suspicious multiple times
            for i in range(3):
                print("Declaring suspicious file replica: " + suspicious_pfns[0])
                # The reason must contain the word "checksum", so that the replica can be declared bad.
                replica_client.declare_suspicious_file_replicas([suspicious_pfns[0], ], 'checksum')
                sleep(1)
            if replica['name'] == self.tmp_file8.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.scope_nopolicy, self.tmp_file8.name, ReplicaState.UNAVAILABLE)

        for replica in replicalist_scope_ignore:
            suspicious_pfns = replica['rses'][self.rse4suspicious_id]
            #  Declare each file as suspicious multiple times
            for i in range(3):
                print("Declaring suspicious file replica: " + suspicious_pfns[0])
                # The reason must contain the word "checksum", so that the replica can be declared bad.
                replica_client.declare_suspicious_file_replicas([suspicious_pfns[0], ], 'checksum')
                sleep(1)
            if replica['name'] == self.tmp_file10.name:
                print("Updating replica state as unavailable: " + replica['rses'][self.rse4recovery_id][0])
                update_replica_state(self.rse4recovery_id, self.scope_ignore, self.tmp_file10.name, ReplicaState.UNAVAILABLE)

        # Gather replica info after setting initial replica statuses
        replicalist_scope_mock = list(list_replicas(dids=self.listdids_mock))
        replicalist_scope_declarebad = list(list_replicas(dids=self.listdids_declarebad))
        replicalist_scope_nopolicy = list(list_replicas(dids=self.listdids_nopolicy))
        replicalist_scope_ignore = list(list_replicas(dids=self.listdids_ignore))

        # Checking if the status changes were effective
        for replica in replicalist_scope_mock:
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
            if replica['name'] == self.tmp_file6.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file12.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        for replica in replicalist_scope_declarebad:
            if replica['name'] == self.tmp_file7.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file9.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file11.name:
                # tmp_file11 should be ignored, as it doesn't have a datatype
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file13.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        for replica in replicalist_scope_nopolicy:
            if replica['name'] == self.tmp_file8.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        for replica in replicalist_scope_ignore:
            if replica['name'] == self.tmp_file10.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        # Checking if self.tmp_file2 was declared as 'BAD' on rse4suspicious
        self.from_date = datetime.utcnow() - timedelta(days=1)
        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4suspicious_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file2.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file3.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file5.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file6.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file7.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file8.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file9.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file10.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file11.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file12.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file13.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist

        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4recovery_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file2.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file3.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file5.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file6.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file7.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file8.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file9.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file10.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file11.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file12.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file13.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist

        # Purposefully not checking for the 'SUSPICIOUS' status on rse4suspicious.
        # The only existing function (to date) gathering info about 'SUSPICIOUS' replicas
        # is used (currently only) from the tested replica_recoverer itself.

        # Write policy file to include test policies
        json_data = []
        with open("/opt/rucio/etc/test_replica_recoverer.json", mode="w") as json_file:
            # Any combination of datatype and scope can be given any action.
            # For the test, the actions for json_testentry1 and json_testentry2 have been arbitrarily chosen.
            # Entries that are higher up in the JSON file have priority over those that are below them.
            json_HITS = {"action": "declare bad", "datatype": ["HITS"], "scope": []}
            json_RAW = {"action": "ignore", "datatype": ["RAW"], "scope": []}
            # json_testentry1 and json_testentry2 need to be above the other entries, otherwise
            # they will always "lose" to an entry with either "datatype": [] or "scope": [].
            # "datatype": [] and "scope": [] are wildcards; they stand for every datatype or scope.
            json_testentry1 = {"action": "ignore", "datatype": ["testtypedeclarebad"], "scope": [str(self.scope_ignore)]}
            json_testentry2 = {"action": "declare bad", "datatype": ["testtypeignore"], "scope": [str(self.scope_declarebad)]}
            json_testentry3 = {"action": "dry run", "datatype": ["testtypedryrun"], "scope": [str(self.scope_declarebad)]}
            json_testentry4 = {"action": "declare bad", "datatype": ["testtypedeclarebad"], "scope": []}
            json_testentry5 = {"action": "ignore", "datatype": ["testtypeignore"], "scope": []}
            json_testentry6 = {"action": "declare bad", "datatype": [], "scope": [str(self.scope_declarebad)]}
            json_testentry7 = {"action": "ignore", "datatype": [], "scope": [str(self.scope_ignore)]}
            json_data.append(json_HITS)
            json_data.append(json_RAW)
            json_data.append(json_testentry1)
            json_data.append(json_testentry2)
            json_data.append(json_testentry3)
            json_data.append(json_testentry4)
            json_data.append(json_testentry5)
            json_data.append(json_testentry6)
            json_data.append(json_testentry7)
            json.dump(json_data, json_file)

    def test_replica_recoverer(self, vo):
        """ REPLICA RECOVERER: Testing declaration of suspicious replicas as bad if they are found available on other RSEs.

            setUp function (above) is supposed to run first
            (nose does this automatically):

            - uploads 6 test files to two test RSEs (rse4recovery, rse4suspicious)
            - prepares their statuses to be as follows:

        # ----------------------------------------------------------------------------------------------------------------------------------------------------
        # Name         State(s) declared on rse4recovery       State(s) declared on rse4suspicious        Scope                     Metadata "datatype"
        # ----------------------------------------------------------------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious (available)                    mock_scope
        # tmp_file2    available                                suspicious + bad (unavailable)            mock_scope
        # tmp_file3    unavailable                              suspicious (available)                    mock_scope                  RAW
        # tmp_file4    unavailable                              suspicious (available)                    mock_scope                  testtypedeclarebad
        # tmp_file5    unavailable                              suspicious (available)                    mock_scope                  testtypenopolicy
        # tmp_file6    unavailable                              suspicious (available)                    mock_scope                  testtypeignore
        # tmp_file7    unavailable                              suspicious (available)                    scope_declarebad            testtypenopolicy
        # tmp_file8    unavailable                              suspicious (available)                    scope_nopolicy              testtypenopolicy
        # tmp_file9    unavailable                              suspicious (available)                    scope_declarebad            testtypeignore
        # tmp_file10   unavailable                              suspicious (available)                    scope_ignore                testtypedeclarebad
        # tmp_file11   unavailable                              suspicious (available)                    scope_declarebad            <none>
        # tmp_file12   unavailable                              suspicious (available)                    mock_scope                  <none>
        # tmp_file13   unavailable                              suspicious (available)                    scope_declarebad            testtypedryrun
        # ----------------------------------------------------------------------------------------------------------------------------------------------------

            - Explaination: Suspicious replicas that are the last remaining copy (unavailable on rse4recovery) are handeled differently depending
                            by their metadata "datatype".
                            - Files that are the last remaining copy, but do not have a data type, are automatically ignored. For this reason, testing
                              just the scope policies (tmp_file7 and tmp_file8) still requires a data type.
                            - RAW files have the poilcy to be ignored.
                            - testtypedeclarebad files are of a fictional type that has the policy of being declared bad.
                            - testtypenopolicy files are of a fictional type that doesn't have a specified policy, meaning they should be ignored by default.
                            - scope_declarebad files belong to a fictional scope that has the policy of being declared bad.
                            - scope_nopolicy files belong to a fictional scope that doesn't have a specified policy, meaning they should be ignored by default.
                            If a policiy is set for the file type and the scope, then the policiy for the file type takes priority (meaning tmp_file9 should be
                            ignored).

            Runs the Test:

            - running suspicious_replica_recoverer

            Concluding:

            - checks that tmp_file1, tmp_file4, tmp_file7, tmp_file9, tmp_file10 were declared as 'BAD' on rse4suspicious

        """

        try:
            run(once=True, younger_than=1, nattempts=2, limit_suspicious_files_on_rse=11, json_file_name="/opt/rucio/etc/test_replica_recoverer.json", sleep_time=0, active_mode=True)
        except KeyboardInterrupt:
            stop()

        # Checking the outcome:
        # We expect to see four changes: tmp_file1, tmp_file4, tmp_file7, tmp_file9, tmp_file10 should be declared as bad on rse4suspicious
        # ----------------------------------------------------------------------------------------------------------------------------------------------------
        # Name         State(s) declared on rse4recovery       State(s) declared on rse4suspicious        Scope                     Metadata "datatype"
        # ----------------------------------------------------------------------------------------------------------------------------------------------------
        # tmp_file1    available                                suspicious + bad (unavailable)            mock_scope                  <none>
        # tmp_file2    available                                suspicious + bad (unavailable)            mock_scope                  <none>
        # tmp_file3    unavailable                              suspicious (available)                    mock_scope                  RAW
        # tmp_file4    unavailable                              suspicious + bad (unavailable)            mock_scope                  testtypedeclarebad
        # tmp_file5    unavailable                              suspicious (available)                    mock_scope                  testtypenopolicy
        # tmp_file6    unavailable                              suspicious (available)                    mock_scope                  testtypeignore
        # tmp_file7    unavailable                              suspicious + bad (unavailable)            scope_declarebad            testtypenopolicy
        # tmp_file8    unavailable                              suspicious (available)                    scope_nopolicy              testtypenopolicy
        # tmp_file9    unavailable                              suspicious + bad (unavailable)            scope_declarebad            testtypeignore
        # tmp_file10   unavailable                              suspicious (available)                    scope_ignore                testtypedeclarebad
        # tmp_file11   unavailable                              suspicious (available)                    scope_declarebad            <none>
        # tmp_file12   unavailable                              suspicious (available)                    mock_scope                  <none>
        # tmp_file13   unavailable                              suspicious (available)                    scope_declarebad            testtypedryrun
        # ----------------------------------------------------------------------------------------------------------------------------------------------------

        # Gather replica info after replica_recoverer has run.
        replicalist_scope_mock = list(list_replicas(dids=self.listdids_mock))
        replicalist_scope_declarebad = list(list_replicas(dids=self.listdids_declarebad))
        replicalist_scope_nopolicy = list(list_replicas(dids=self.listdids_nopolicy))
        replicalist_scope_ignore = list(list_replicas(dids=self.listdids_ignore))

        for replica in replicalist_scope_mock:
            if replica['name'] == self.tmp_file1.name or replica['name'] == self.tmp_file2.name:
                assert (self.rse4suspicious_id in replica['states']) is False
                assert replica['states'][self.rse4recovery_id] == 'AVAILABLE'
            if replica['name'] == self.tmp_file3.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file4.name:
                # The 'states' key doesn't exist if the replica isn't available on at least one RSE
                assert not replica.get('states')
            if replica['name'] == self.tmp_file5.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file12.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        for replica in replicalist_scope_declarebad:
            if replica['name'] == self.tmp_file7.name:
                # The 'states' key doesn't exist if the replica isn't available on at least one RSE
                assert not replica.get('states')
            if replica['name'] == self.tmp_file9.name:
                assert not replica.get('states')
            if replica['name'] == self.tmp_file11.name:
                # tmp_file11 should have been ignored, as it doesn't have a datatype
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False
            if replica['name'] == self.tmp_file13.name:
                # tmp_file13 should have been ignored, as it is running as a dry run
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        for replica in replicalist_scope_nopolicy:
            if replica['name'] == self.tmp_file8.name:
                assert replica['states'][self.rse4suspicious_id] == 'AVAILABLE'
                assert (self.rse4recovery_id in replica['states']) is False

        for replica in replicalist_scope_ignore:
            if replica['name'] == self.tmp_file10.name:
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
        assert (self.tmp_file6.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file7.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file8.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file9.name, self.rse4suspicious_id, BadFilesStatus.BAD) in bad_checklist
        assert (self.tmp_file10.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file11.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file12.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file13.name, self.rse4suspicious_id, BadFilesStatus.BAD) not in bad_checklist

        bad_replicas_list = list_bad_replicas_status(rse_id=self.rse4recovery_id, younger_than=self.from_date, vo=vo)
        bad_checklist = [(badf['name'], badf['rse_id'], badf['state']) for badf in bad_replicas_list]

        assert (self.tmp_file1.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file2.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file3.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file4.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file5.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file6.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file7.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file8.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file9.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file10.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file11.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file12.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
        assert (self.tmp_file13.name, self.rse4recovery_id, BadFilesStatus.BAD) not in bad_checklist
