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

from nose.tools import *
from paste.fixture import TestApp
from uuid import uuid4 as uuid

from sqlalchemy import create_engine

from rucio.common.config import config_get
from rucio.core.account import add_account, check_account, del_account
from rucio.core.account import get_account_status, account_status, set_account_status
from rucio.db import models1 as models
from rucio.db.session import build_database
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app


class TestAccount_core_api():
    def setUp(self):
        build_database()

    def testDown(self):
        pass

    def test_create_and_check_for_user(self):
        """ ACCOUNT (CORE): Test the creation, query, and deletion of an account """
        usr = str(uuid())
        invalid_usr = str(uuid())
        add_account(usr, 'user')
        assert_equal(check_account(usr), True)  # Check that the account exists
        assert_equal(check_account(invalid_usr), False)  # Check for a non existant account
        del_account(usr)

    def test_account_status(self):
        """ ACCOUNT (CORE): Test changing and quering account status """
        usr = str(uuid())
        add_account(usr, 'user')
        assert_equal(get_account_status(usr), account_status.active)  # Should be active by default
        set_account_status(usr, account_status.inactive)
        assert_equal(get_account_status(usr), account_status.inactive)
        set_account_status(usr, account_status.disabled)
        assert_equal(get_account_status(usr), account_status.disabled)
        set_account_status(usr, account_status.active)
        assert_equal(get_account_status(usr), account_status.active)
        del_account(usr)


class TestAccount():

    def setUp(self):
        engine = create_engine(config_get('database', 'default'))
        models.register_models(engine)

    def tearDown(self):
        engine = create_engine(config_get('database', 'default'))
        models.unregister_models(engine)

    def test_create_user_success(self):
        """ ACCOUNT (REST): send a POST to create a new user """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/account/testuser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

    def test_create_user_failure(self):
        """ ACCOUNT (REST): send a POST with an existing user to test the error case """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers = {'Rucio-Type': 'user', 'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r1 = TestApp(account_app.wsgifunc(*mw)).post('/account/testuser', headers=headers, expect_errors=True)
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/account/testuser', headers=headers, expect_errors=True)
        assert_equal(r2.status, 500)

    def test_get_user_success(self):
        """ ACCOUNT (REST): send a GET to retrieve the infos of the new user """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/account/testuser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).get('/account/testuser', headers=headers3, expect_errors=True)
        body = json.loads(r3.body)
        assert_equal(body['account'], 'testuser')
        assert_equal(r3.status, 200)

    def test_get_user_failure(self):
        """ ACCOUNT (REST): send a GET with a wrong user test the error """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': token}
        r2 = TestApp(account_app.wsgifunc(*mw)).get('/account/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 500)

    def test_del_user_success(self):
        """ ACCOUNT (REST): send a DELETE to disable the new user """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/account/testuser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).delete('/account/testuser', headers=headers3, expect_errors=True)
        assert_equal(r3.status, 200)

        headers4 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r4 = TestApp(account_app.wsgifunc(*mw)).get('/account/testuser', headers=headers4, expect_errors=True)
        body = json.loads(r4.body)
        assert_true(body['deleted'])
        assert_equal(r3.status, 200)

    def test_del_user_failure(self):
        """ ACCOUNT (REST): send a DELETE with a wrong user to test the error """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).delete('/account/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 500)
