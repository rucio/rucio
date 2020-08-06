# Copyright 2017-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import unittest
from datetime import datetime

from rucio.client.didclient import DIDClient
from rucio.client.lifetimeclient import LifetimeClient
from rucio.common.utils import generate_uuid
from rucio.db.sqla.constants import DIDType


class TestDIDClients(unittest.TestCase):

    def setUp(self):
        self.did_client = DIDClient()
        self.lifetime_client = LifetimeClient()

    def test_create_and_check_lifetime_exception(self):
        """ LIFETIME (CLIENT): Test the creation of a Lifetime Model exception """
        tmp_scope = 'mock'
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        self.did_client.add_did(scope=tmp_scope, name=tmp_dsn1, type=DIDType.DATASET)
        dids = [{'scope': tmp_scope, 'name': tmp_dsn1, 'did_type': DIDType.DATASET}, ]
        exceptions = self.lifetime_client.list_exceptions()
        exception_id = self.lifetime_client.add_exception(dids, account='root', pattern='wekhewfk', comments='This is a comment', expires_at=datetime.now())
        exceptions = [exception['id'] for exception in self.lifetime_client.list_exceptions()]
        assert exception_id in exceptions
