# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2019-2021
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import os
import unittest

import pytest

from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid
from rucio.core.rse import get_rse_id, get_rse_usage
from rucio.daemons.abacus import rse
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper2
from rucio.daemons.undertaker import undertaker
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from rucio.tests.common import file_generator


@pytest.mark.noparallel(reason='uses daemon, failing in parallel to other tests, updates account')
class TestAbacusRSE(unittest.TestCase):
    account = 'root'
    scope = 'mock'
    rse = 'MOCK4'
    file_sizes = 2
    vo = {}

    @classmethod
    def setUpClass(cls):
        cls.upload_client = UploadClient()
        cls.session = get_session()

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}

        cls.rse_id = get_rse_id(cls.rse, session=cls.session, **cls.vo)

    @classmethod
    def tearDownClass(cls):
        undertaker.run(once=True)
        cleaner.run(once=True)
        if cls.vo:
            reaper2.run(once=True, include_rses='vo=%s&(%s)' % (cls.vo['vo'], cls.rse), greedy=True)
        else:
            reaper2.run(once=True, include_rses=cls.rse, greedy=True)

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
        assert rse_usage['used'] == len(self.files) * self.file_sizes
        rse_usage_from_rucio = get_rse_usage(rse_id=self.rse_id, source='rucio')[0]
        assert rse_usage_from_rucio['used'] == len(self.files) * self.file_sizes
        rse_usage_from_unavailable = get_rse_usage(rse_id=self.rse_id, source='unavailable')
        assert len(rse_usage_from_unavailable) == 0

        # Delete files -> rse usage should decrease
        from rucio.daemons.reaper.reaper2 import REGION
        REGION.invalidate()
        cleaner.run(once=True)
        if self.vo:
            reaper2.run(once=True, include_rses='vo=%s&(%s)' % (self.vo['vo'], self.rse), greedy=True)
        else:
            reaper2.run(once=True, include_rses=self.rse, greedy=True)
        rse.run(once=True)
        rse_usage = get_rse_usage(rse_id=self.rse_id)[0]
        assert rse_usage['used'] == 0
        rse_usage_from_rucio = get_rse_usage(rse_id=self.rse_id, source='rucio')[0]
        assert rse_usage_from_rucio['used'] == 0
        rse_usage_from_unavailable = get_rse_usage(rse_id=self.rse_id, source='unavailable')
        assert len(rse_usage_from_unavailable) == 0
