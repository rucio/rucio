# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import uuid

from nose.tools import *
from paste.fixture import TestApp

from rucio.core.account import add_account, del_account
from rucio.core.identity import add_identity, add_account_identity
from rucio.common.config import config_get
from rucio.db.session import build_database, destroy_database
from rucio.web.rest.authentication import app


class TestGET():

    def setUp(self):
        build_database()
        self.account = str(uuid.uuid4())
        add_account(self.account, 'user')
        add_identity('ddmlab', 'userpass', password='secret')
        add_account_identity('ddmlab', 'userpass', self.account)

    def tearDown(self):
        destroy_database()

    def test_auth_header_userpass_fail(self):
        """AUTHENTICATION (REST): Username and password (wrong credentials)."""

        mw = []
        headers = {'Rucio-Account': 'wrong', 'Rucio-Username': 'wrong', 'Rucio-Password': 'wrong'}
        r = TestApp(app.wsgifunc(*mw)).get('/auth/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 401)

    def test_auth_header_userpass_success(self):
        """AUTHENTICATION (REST): Username and password (correct credentials)."""

        mw = []
        headers = {'Rucio-Account': self.account, 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r = TestApp(app.wsgifunc(*mw)).get('/auth/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        assert_equal(len(r.header('Rucio-Auth-Token')), 32)


class TestPUT():

    pass


class TestPOST():

    pass


class TestDELETE():

    pass
