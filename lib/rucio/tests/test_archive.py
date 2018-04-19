# Copyright 2017-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018

from nose.tools import assert_equal

from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient

from rucio.common.utils import generate_uuid


class TestDIDClients(object):

    def __init__(self):
        self.did_client = DIDClient()
        self.replica_client = ReplicaClient()

    def test_add_and_list_archive(self):
        """  ARCHIVE (CLIENT): Add files to archive and list the content."""
        scope, rse = 'mock', 'MOCK'
        archive_files = ['file_' + generate_uuid() + '.zip' for _ in range(2)]
        files = []
        for i in range(10):
            files.append({'scope': scope, 'name': 'lfn.%s' % str(generate_uuid()),
                          'bytes': 724963570,
                          'adler32': '0cc737eb',
                          'type': 'FILE',
                          'meta': {'guid': str(generate_uuid())}})
        for archive_file in archive_files:

            self.replica_client.add_replicas(rse=rse, files=[{'scope': scope,
                                                              'name': archive_file,
                                                              'bytes': 1,
                                                              'adler32': '0cc737eb'}])

            self.did_client.add_files_to_archive(scope=scope, name=archive_file, files=files)

            content = [fil for fil in self.did_client.list_archive_content(scope=scope,
                                                                           name=archive_file)]

            assert_equal(len(content), 10)
