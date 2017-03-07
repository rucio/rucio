# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2017


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
        archive_file = 'file_' + generate_uuid() + '.zip'
        files = []
        for i in xrange(10):
            files.append({'scope': scope, 'name': 'lfn.%s' % str(generate_uuid()),
                          'bytes': 724963570L,
                          'adler32': '0cc737eb',
                          'type': 'FILE',
                          'meta': {'guid': str(generate_uuid())}})

        self.replica_client.add_replicas(rse=rse, files=[{'scope': scope,
                                                          'name': archive_file,
                                                          'bytes': 1L,
                                                          'adler32': '0cc737eb'}])

        self.did_client.add_files_to_archive(scope=scope,
                                             name=archive_file,
                                             files=files)

        content = [fil for fil in self.did_client.list_archive_content(scope=scope,
                                                                       name=archive_file)]

        assert_equal(len(content), 10)
