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

import logging

import nose.tools
import os.path

from rucio.client.client import Client
from rucio.client.downloadclient import DownloadClient
from rucio.client.uploadclient import UploadClient
from rucio.common.utils import generate_uuid
from rucio.tests.common import file_generator


class TestDownloadClient(object):

    def setup(self):
        logger = logging.getLogger('dlul_client')
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)
        self.client = Client()
        self.upload_client = UploadClient(_client=self.client, logger=logger)
        self.download_client = DownloadClient(client=self.client, logger=logger)

    def create_and_upload_tmp_file(self, rse, scope='mock'):
        file_path = file_generator()
        item = {'path': file_path,
                'rse': rse,
                'did_scope': scope,
                'did_name': os.path.basename(file_path),
                'guid': generate_uuid()}
        nose.tools.assert_equal(self.upload_client.upload([item]), 0)
        return item

    def test_download_item(self):
        """ DOWNLOAD (CLIENT): download DIDs. """
        item = self.create_and_upload_tmp_file('MOCK4')
        scope = item['did_scope']
        name = item['did_name']
        uuid = item['guid']

        # Download specific DID
        result = self.download_client.download_dids([{'did': '%s:%s' % (scope, name)}])
        nose.tools.assert_true(result)

        # Download with wildcard
        result = self.download_client.download_dids([{'did': '%s:%s' % (scope, name[:-2] + '*')}])
        nose.tools.assert_true(result)

        # Download with filter
        result = self.download_client.download_dids([{'filters': {'guid': uuid, 'scope': scope}}])
        nose.tools.assert_true(result)

        # Download with wildcard and name
        result = self.download_client.download_dids([{'did': '%s:%s' % (scope, '*'), 'filters': {'guid': uuid}}])
        nose.tools.assert_true(result)
