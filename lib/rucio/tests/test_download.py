# Copyright 2019 CERN for the benefit of the ATLAS collaboration.
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
# - Tobias Wegner <twegner@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

import logging
import shutil

import nose.tools
import os.path

from rucio.client.client import Client
from rucio.client.downloadclient import DownloadClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid
from rucio.tests.common import file_generator


class TestDownloadClient(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        logger = logging.getLogger('dlul_client')
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)
        self.client = Client()
        self.upload_client = UploadClient(_client=self.client, logger=logger)
        self.download_client = DownloadClient(client=self.client, logger=logger)

        self.file_path = file_generator()
        self.scope = 'mock'
        self.name = os.path.basename(self.file_path)
        self.rse = 'MOCK4'
        self.guid = generate_uuid()

        item = {'path': self.file_path,
                'rse': self.rse,
                'did_scope': self.scope,
                'did_name': self.name,
                'guid': self.guid}
        nose.tools.assert_equal(self.upload_client.upload([item]), 0)

    def teardown(self):
        shutil.rmtree('mock')

    def test_download_item(self):
        """ DOWNLOAD (CLIENT): Download DIDs """

        # Download specific DID
        result = self.download_client.download_dids([{'did': '%s:%s' % (self.scope, self.name)}])
        nose.tools.assert_true(result)

        # Download with wildcard
        result = self.download_client.download_dids([{'did': '%s:%s' % (self.scope, self.name[:-2] + '*')}])
        nose.tools.assert_true(result)

        # Download with filter
        result = self.download_client.download_dids([{'filters': {'guid': self.guid, 'scope': self.scope}}])
        nose.tools.assert_true(result)

        # Download with wildcard and name
        result = self.download_client.download_dids([{'did': '%s:%s' % (self.scope, '*'), 'filters': {'guid': self.guid}}])
        nose.tools.assert_true(result)
