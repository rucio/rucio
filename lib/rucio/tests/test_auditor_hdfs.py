'''
  Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne,  <vincent.garonne@cern.ch> , 2017
'''
import os
import shutil
import string
import tempfile


from datetime import datetime
from nose.tools import eq_

from rucio.daemons.auditor import hdfs
from rucio.tests.common import stubbed


class FakeHDFSGet(object):
    '''
    FakeHDFSGet
    '''
    def __init__(self, files=[]):
        '''
        __init__
        '''
        self.files = files

    def __call__(self, src_path, dst_dir):
        '''
        __call__
        '''
        # src_path is ignored, it is assumed a directory is requested
        for content, name in self.files:
            with open(os.path.join(dst_dir, name), 'w') as fichier:
                fichier.write(str(content) + '\n')


class TestReplicaFromHDFS(object):
    '''
    TestReplicaFromHDFS
    '''
    def setup(self):
        '''
        setup
        '''
        self.work_dir = tempfile.mkdtemp()

    def teardown(self):
        '''
        teardown
        '''
        shutil.rmtree(self.work_dir)

    def test_replica_from_hdfs_download_merges_the_file_parts_in_order(self):
        '''test_replica_from_hdfs_download_merges_the_file_parts_in_order'''
        files = reversed(list(enumerate(string.lowercase[:5])))
        with stubbed(hdfs._hdfs_get, FakeHDFSGet(files)):
            merged_file_path = hdfs.ReplicaFromHDFS.download(
                'FAKE_RSE',
                datetime.now(),
                cache_dir=self.work_dir,
            )

        with open(merged_file_path) as f:
            eq_('01234', f.read().replace('\n', ''))

    def test_replica_from_hdfs_download_reads_files_bigger_than_buffer_size(self):
        '''test_replica_from_hdfs_download_reads_files_bigger_than_buffer_size'''
        files = [
            (string.digits[:5], 'a'),
            (string.digits[5:10], 'b'),
        ]
        with stubbed(hdfs._hdfs_get, FakeHDFSGet(files)):
            merged_file_path = hdfs.ReplicaFromHDFS.download(
                'FAKE_RSE',
                datetime.now(),
                cache_dir=self.work_dir,
                buffer_size=2,
            )

        with open(merged_file_path) as fichier:
            eq_('0123456789', fichier.read().replace('\n', ''))
