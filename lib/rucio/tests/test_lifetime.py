"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
"""

from datetime import datetime

from nose.tools import assert_in

from rucio.client.didclient import DIDClient
from rucio.client.lifetimeclient import LifetimeClient
from rucio.common.utils import generate_uuid
from rucio.db.sqla.constants import DIDType


class TestDIDClients:

    def __init__(self):
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
        assert_in(exception_id, exceptions)
