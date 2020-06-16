# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin, <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from nose.tools import assert_equal

import os

from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid
from rucio.core.rse import get_rse_id, get_rse_usage
from rucio.daemons.undertaker import undertaker
from rucio.daemons.abacus import rse
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.tests.common import file_generator


class TestAbacusRSE():
    def setUp(self):
        self.account = 'root'
        self.scope = 'mock'
        self.rse = 'MOCK4'
        self.file_sizes = 2
        self.upload_client = UploadClient()
        self.session = get_session()

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        self.rse_id = get_rse_id(self.rse, session=self.session, **self.vo)

    def tearDown(self):
        undertaker.run(once=True)
        cleaner.run(once=True)
        if self.vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (self.vo['vo'], self.rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=self.rse, greedy=True)

    def test_abacus_rse(self):
        """ ABACUS (RSE): Test update of RSE usage. """
        # Get RSE usage of all sources
        self.session.query(models.UpdatedRSECounter).delete()  # pylint: disable=no-member
        self.session.query(models.RSEUsage).delete()  # pylint: disable=no-member
        self.session.commit()  # pylint: disable=no-member

        # Upload files -> RSE usage should increase
        self.files = [{'did_scope': self.scope, 'did_name': 'file_' + generate_uuid(), 'path': file_generator(size=self.file_sizes), 'rse': self.rse, 'lifetime': -1} for i in range(0, 2)]
        self.upload_client.upload(self.files)
        [os.remove(file['path']) for file in self.files]
        rse.run(once=True)
        rse_usage = get_rse_usage(rse_id=self.rse_id)[0]
        assert_equal(rse_usage['used'], len(self.files) * self.file_sizes)
        rse_usage_from_rucio = get_rse_usage(rse_id=self.rse_id, source='rucio')[0]
        assert_equal(rse_usage_from_rucio['used'], len(self.files) * self.file_sizes)
        rse_usage_from_unavailable = get_rse_usage(rse_id=self.rse_id, source='unavailable')
        assert_equal(len(rse_usage_from_unavailable), 0)

        # Delete files -> rse usage should decrease
        cleaner.run(once=True)
        if self.vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (self.vo['vo'], self.rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=self.rse, greedy=True)
        rse.run(once=True)
        rse_usage = get_rse_usage(rse_id=self.rse_id)[0]
        assert_equal(rse_usage['used'], 0)
        rse_usage_from_rucio = get_rse_usage(rse_id=self.rse_id, source='rucio')[0]
        assert_equal(rse_usage_from_rucio['used'], 0)
        rse_usage_from_unavailable = get_rse_usage(rse_id=self.rse_id, source='unavailable')
        assert_equal(len(rse_usage_from_unavailable), 0)
