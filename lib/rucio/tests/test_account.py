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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011

from json import dumps, loads

from nose.tools import assert_equal, assert_false, assert_true, raises
from paste.fixture import TestApp

from rucio.client.accountclient import AccountClient
from rucio.common.exception import AccountNotFound, Duplicate
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account, account_exists, del_account
from rucio.core.account import get_account_status, account_status, set_account_status
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app


class TestAccountCoreApi():

    def setUp(self):
        build_database(echo=False)

    def tearDown(self):
        destroy_database(echo=False)

    def test_create_and_check_for_user(self):
        """ ACCOUNT (CORE): Test the creation, query, and deletion of an account """
        usr = str(uuid())
        invalid_usr = str(uuid())
        add_account(usr, 'user')
        assert_equal(account_exists(usr), True)
        assert_equal(account_exists(invalid_usr), False)
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


class TestAccountRestApi():

    def setUp(self):
        build_database(echo=False)
        create_root_account()

    def tearDown(self):
        destroy_database(echo=False)

    def test_create_user_success(self):
        """ ACCOUNT (REST): send a POST to create a new user """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testuser', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

    def test_create_user_failure(self):
        """ ACCOUNT (REST): send a POST with an existing user to test the error case """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testuser', 'accountType': 'user'})
        r1 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers, params=data, expect_errors=True)
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers, params=data, expect_errors=True)

        assert_equal(r2.status, 409)

    def test_create_user_non_json_body(self):
        """ ACCOUNT (REST): send a POST with a non json body"""
        mw = []
        headers = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        token = str(r.header('Rucio-Auth-Token'))

        headers = {'Rucio-Auth-Token': str(token)}
        data = {'datasetName': 'dataset'}
        ret = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers, params=data, expect_errors=True)

        assert_equal(ret.header('ExceptionClass'), 'ValueError')
        assert_equal(ret.normal_body, 'ValueError: cannot decode json parameter dictionary')
        assert_equal(ret.status, 400)

    def test_create_user_missing_parameter(self):
        """ ACCOUNT (REST): send a POST with a missing parameter"""
        mw = []
        headers = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        token = str(r.header('Rucio-Auth-Token'))

        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'account'})
        ret = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers, params=data, expect_errors=True)

        assert_equal(ret.header('ExceptionClass'), 'KeyError')
        assert_equal(ret.normal_body, "KeyError: \'accountType\' not defined")
        assert_equal(ret.status, 400)

    def test_create_user_not_json_dict(self):
        """ ACCOUNT (REST): send a POST with a non dictionary json body"""
        mw = []
        headers = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        token = str(r.header('Rucio-Auth-Token'))

        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps(('accountName', 'account'))
        r = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers, params=data, expect_errors=True)

        assert_equal(r.header('ExceptionClass'), 'TypeError')
        assert_equal(r.normal_body, "TypeError: body must be a json dictionary")
        assert_equal(r.status, 400)

    def test_get_user_success(self):
        """ ACCOUNT (REST): send a GET to retrieve the infos of the new user """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testuser', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).get('/testuser', headers=headers3, expect_errors=True)
        body = loads(r3.body)
        assert_equal(body['account'], 'testuser')
        assert_equal(r3.status, 200)

    def test_get_user_failure(self):
        """ ACCOUNT (REST): send a GET with a wrong user test the error """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': token}
        r2 = TestApp(account_app.wsgifunc(*mw)).get('/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 404)

    def test_del_user_success(self):
        """ ACCOUNT (REST): send a DELETE to disable the new user """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testuser', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).delete('/testuser', headers=headers3, expect_errors=True)
        assert_equal(r3.status, 200)

        headers4 = {'Rucio-Auth-Token': str(token)}
        r4 = TestApp(account_app.wsgifunc(*mw)).get('/testuser', headers=headers4, expect_errors=True)
        body = loads(r4.body)
        assert_true(body['deleted'])
        assert_equal(r3.status, 200)

    def test_del_user_failure(self):
        """ ACCOUNT (REST): send a DELETE with a wrong user to test the error """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).delete('/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 404)

    def test_whoami_account(self):
        """ ACCOUNT (REST): Test the whoami method."""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).get('/whoami', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 303)

    def test_list_account(self):
        """ ACCOUNT (REST): send a GET to list all accounts."""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        acc_list = ['test' + str(i) for i in xrange(5)]
        for account in acc_list:
            data = dumps({'accountName': account, 'accountType': 'user'})
            r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
            assert_equal(r2.status, 201)

        r3 = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        assert_equal(r3.status, 200)
        svr_list = loads(r3.body)
        for account in acc_list:
            if account not in svr_list:
                assert_true(False)


class TestAccountClient():

    def setUp(self):
        build_database(echo=False)
        create_root_account()
        creds = {'username': 'ddmlab', 'password': 'secret'}
        self.client = AccountClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

    def tearDown(self):
        destroy_database(echo=False)

    def test_create_account_success(self):
        """ ACCOUNT (CLIENTS): create a new account."""
        ret = self.client.create_account(str(uuid()), 'user')
        assert_true(ret)

    @raises(Duplicate)
    def test_create_account_duplicate(self):
        """ ACCOUNT (CLIENTS): try to create a duplicate account."""
        account = str(uuid())
        type = 'user'
        self.client.create_account(account, type)
        self.client.create_account(account, type)

    def test_get_account(self):
        """ ACCOUNT (CLIENTS): get information about account."""
        account = str(uuid())
        self.client.create_account(account, 'user')
        acc_info = self.client.get_account(account)
        assert_equal(acc_info['account'], account)

    @raises(AccountNotFound)
    def test_get_account_notfound(self):
        """ ACCOUNT (CLIENTS): try to get information about not existing account."""
        account = str(uuid())
        self.client.get_account(account)

    def test_disable_account(self):
        """ ACCOUNT (CLIENTS): try to disable account."""
        account = str(uuid())
        self.client.create_account(account, 'user')
        acc_info = self.client.get_account(account)
        assert_false(acc_info['deleted'])
        self.client.disable_account(account)
        acc_info = self.client.get_account(account)
        assert_true(acc_info['deleted'])

    @raises(AccountNotFound)
    def test_disable_account_notfound(self):
        """ ACCOUNT (CLIENTS): try to disable not existing account."""
        account = str(uuid())
        self.client.disable_account(account)

    def test_list_accounts(self):
        """ ACCOUNT (CLIENTS): get list of all accounts."""
        acc_list = [str(uuid()) + str(i) for i in xrange(5)]

        for account in acc_list:
            self.client.create_account(account, 'user')

        svr_list = self.client.list_accounts()

        for account in acc_list:
            if account not in svr_list:
                assert_true(False)
