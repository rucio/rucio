# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import os
import unittest

from rucio.client.accountclient import AccountClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.account import get_usage_history
from rucio.core.account_counter import update_account_counter_history
from rucio.core.account_limit import get_local_account_usage, set_local_account_limit
from rucio.core.rse import get_rse_id
from rucio.daemons.abacus import account
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.daemons.undertaker import undertaker
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from rucio.tests.common import file_generator


class TestAbacusAccount(unittest.TestCase):
    rse = 'MOCK4'
    file_sizes = 2
    vo = {}

    @classmethod
    def setUpClass(cls):
        cls.upload_client = UploadClient()
        cls.account_client = AccountClient()
        cls.session = get_session()

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}

        cls.account = InternalAccount('root', **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.rse_id = get_rse_id(cls.rse, session=cls.session, **cls.vo)

    @classmethod
    def tearDownClass(cls):
        undertaker.run(once=True)
        cleaner.run(once=True)
        if cls.vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (cls.vo['vo'], cls.rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=cls.rse, greedy=True)

    def test_abacus_account(self):
        """ ABACUS (ACCOUNT): Test update of account usage """
        self.session.query(models.UpdatedAccountCounter).delete()  # pylint: disable=no-member
        self.session.query(models.AccountUsage).delete()  # pylint: disable=no-member
        self.session.commit()  # pylint: disable=no-member

        # Upload files -> account usage should increase
        self.files = [{'did_scope': self.scope.external, 'did_name': 'file_' + generate_uuid(), 'path': file_generator(size=self.file_sizes), 'rse': self.rse, 'lifetime': -1} for i in range(0, 2)]
        self.upload_client.upload(self.files)
        [os.remove(file['path']) for file in self.files]
        account.run(once=True)
        account_usage = get_local_account_usage(account=self.account, rse_id=self.rse_id)[0]
        assert account_usage['bytes'] == len(self.files) * self.file_sizes
        assert account_usage['files'] == len(self.files)

        # Update and check the account history with the core method
        update_account_counter_history(account=self.account, rse_id=self.rse_id)
        usage_history = get_usage_history(rse_id=self.rse_id, account=self.account)
        assert usage_history[-1]['bytes'] == len(self.files) * self.file_sizes
        assert usage_history[-1]['files'] == len(self.files)

        # Check the account history with the client
        usage_history = self.account_client.get_account_usage_history(rse=self.rse, account=self.account.external)
        assert usage_history[-1]['bytes'] == len(self.files) * self.file_sizes
        assert usage_history[-1]['files'] == len(self.files)

        # Delete rules -> account usage should decrease
        cleaner.run(once=True)
        account.run(once=True)
        # set account limit because return value of get_local_account_usage differs if a limit is set or not
        set_local_account_limit(account=self.account, rse_id=self.rse_id, bytes=10)
        account_usages = get_local_account_usage(account=self.account, rse_id=self.rse_id)[0]
        assert account_usages['bytes'] == 0
        assert account_usages['files'] == 0
