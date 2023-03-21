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

import os
import string
from datetime import datetime
from unittest import mock

import pytest

from rucio.daemons.auditor import hdfs


class FakeHDFSGet(object):
    def __init__(self, files=[]):
        self.files = files

    def __call__(self, src_path, dst_dir):
        # src_path is ignored, it is assumed a directory is requested
        for content, name in self.files:
            with open(os.path.join(dst_dir, name), 'w') as fichier:
                fichier.write(str(content) + '\n')


@pytest.mark.xfail
@mock.patch('rucio.daemons.auditor.hdfs._hdfs_get')
def test_replica_from_hdfs_download_merges_the_file_parts_in_order(tmp_path, mock_hdfs_get):
    files = reversed(list(enumerate(string.ascii_lowercase[:5])))
    mock_hdfs_get.return_value = FakeHDFSGet(files)
    merged_file_path = hdfs.ReplicaFromHDFS.download(
        'FAKE_RSE',
        datetime.utcnow(),
        cache_dir=tmp_path,
    )

    with open(merged_file_path) as f:
        assert '01234' == f.read().strip()


@pytest.mark.xfail
@mock.patch('rucio.daemons.auditor.hdfs._hdfs_get')
def test_replica_from_hdfs_download_reads_files_bigger_than_buffer_size(tmp_path, mock_hdfs_get):
    files = [
        (string.digits[:5], 'a'),
        (string.digits[5:10], 'b'),
    ]
    mock_hdfs_get.return_value = FakeHDFSGet(files)
    merged_file_path = hdfs.ReplicaFromHDFS.download(
        'FAKE_RSE',
        datetime.utcnow(),
        cache_dir=tmp_path,
        buffer_size=2,
    )

    with open(merged_file_path) as fichier:
        assert '0123456789' == fichier.read().strip()
