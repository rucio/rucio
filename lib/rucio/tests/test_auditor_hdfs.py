# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Fernando López <felopez@cern.ch>, 2015-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

import os
import shutil
import string
import sys
import tempfile
import unittest
from datetime import datetime

import pytest

from rucio.daemons.auditor import hdfs

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock


class FakeHDFSGet(object):
    def __init__(self, files=[]):
        self.files = files

    def __call__(self, src_path, dst_dir):
        # src_path is ignored, it is assumed a directory is requested
        for content, name in self.files:
            with open(os.path.join(dst_dir, name), 'w') as fichier:
                fichier.write(str(content) + '\n')


class TestReplicaFromHDFS(unittest.TestCase):
    def setUp(self):
        self.work_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.work_dir)

    @pytest.mark.xfail
    @mock.patch('rucio.daemons.auditor.hdfs._hdfs_get')
    def test_replica_from_hdfs_download_merges_the_file_parts_in_order(self, mock_hdfs_get):
        files = reversed(list(enumerate(string.ascii_lowercase[:5])))
        mock_hdfs_get.return_value = FakeHDFSGet(files)
        merged_file_path = hdfs.ReplicaFromHDFS.download(
            'FAKE_RSE',
            datetime.now(),
            cache_dir=self.work_dir,
        )

        with open(merged_file_path) as f:
            assert '01234' == f.read().strip()

    @pytest.mark.xfail
    @mock.patch('rucio.daemons.auditor.hdfs._hdfs_get')
    def test_replica_from_hdfs_download_reads_files_bigger_than_buffer_size(self, mock_hdfs_get):
        files = [
            (string.digits[:5], 'a'),
            (string.digits[5:10], 'b'),
        ]
        mock_hdfs_get.return_value = FakeHDFSGet(files)
        merged_file_path = hdfs.ReplicaFromHDFS.download(
            'FAKE_RSE',
            datetime.now(),
            cache_dir=self.work_dir,
            buffer_size=2,
        )

        with open(merged_file_path) as fichier:
            assert '0123456789' == fichier.read().strip()
