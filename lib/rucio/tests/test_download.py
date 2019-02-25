# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from nose.tools import assert_true

from rucio.client.downloadclient import DownloadClient
from rucio.common.utils import generate_uuid
from rucio.tests.common import execute, file_generator


class TestDownloadClient(object):

    def test_download_item(self):
        """ DOWNLOAD (CLIENT): download DIDs. """
        download_client = DownloadClient()
        tmp_file1 = file_generator()
        scope = 'mock'
        name = tmp_file1[5:]
        uuid = generate_uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --guid {2} {3}'.format('MOCK4', scope, uuid, tmp_file1)
        exitcode, out, err = execute(cmd)

        # Download specific DID
        result = download_client.download_dids([{'did': '%s:%s' % (scope, name)}])
        assert_true(result)

        # Download with wildcard
        result = download_client.download_dids([{'did': '%s:%s' % (scope, name[:10] + '*')}])
        assert_true(result)

        # Download with filter
        result = download_client.download_dids([{'filters': {'guid': uuid, 'scope': scope}}])
        assert_true(result)

        # Download with wildcard and name
        result = download_client.download_dids([{'did': '%s:%s' % (scope, '*'), 'filters': {'guid': uuid}}])
        assert_true(result)
