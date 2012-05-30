# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

import json

from paste.fixture import TestApp
from nose.tools import *

from sqlalchemy import create_engine

from rucio.common.config import config_get
from rucio.common import exception
from rucio.core.scope import bulk_add_scopes
from rucio.core.account import add_account
from rucio.db import models1 as models
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app
from rucio.web.rest.scope import app as scope_app


class TestScope():

    def setUp(self):
        engine = create_engine(config_get('database', 'default'))
        models.register_models(engine)
        self.user = 'valid_user'
        self.user_type = 'user'
        self.scopes = ['test_scope_' + str(i) for i in range(5)]
        try:
            add_account(self.user, self.user_type)
        except exception.Duplicate:
            pass  # Account already exists, no need to create it

    def tearDown(self):
        engine = create_engine(config_get('database', 'default'))
        models.unregister_models(engine)

    def test_scope_success(self):
        """ send a POST to create a new account and scope """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/account/testuser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(scope_app.wsgifunc(*mw)).post('/scope/testuser/testscope', headers=headers3, expect_errors=True)

        assert_equal(r3.status, 201)

    def test_scope_failure(self):
        """ send a POST to create a new scope for a not existing account to test the error"""
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(scope_app.wsgifunc(*mw)).post('/scope/testuser/testscope', headers=headers2, expect_errors=True)

        assert_equal(r2.status, 500)

    def test_bulk_add_scopes(self):
        """ SCOPE (CORE): bulk create multiple scopes """

        bulk_add_scopes(self.scopes, self.user, skipExisting=True)
