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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

from json import dumps, loads

from nose.tools import assert_equal, assert_true, assert_raises, raises
from paste.fixture import TestApp

from rucio.api.account import add_account, account_exists, del_account
from rucio.api.account import get_account_status, set_account_status
from rucio.client.accountclient import AccountClient
from rucio.common.exception import AccountNotFound, Duplicate, InvalidObject
from rucio.common.utils import generate_uuid as uuid
from rucio.db.sqla.constants import AccountStatus
from rucio.tests.common import account_name_generator
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app


class TestAccountCoreApi():

    def test_create_and_check_for_user(self):
        """ ACCOUNT (CORE): Test the creation, query, and deletion of an account """
        usr = account_name_generator()
        invalid_usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root')
        assert_equal(account_exists(usr), True)
        assert_equal(account_exists(invalid_usr), False)
        del_account(usr, 'root')

    def test_account_status(self):
        """ ACCOUNT (CORE): Test changing and quering account status """
        usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root')
        assert_equal(get_account_status(usr), AccountStatus.ACTIVE)  # Should be active by default
        set_account_status(usr, AccountStatus.SUSPENDED)
        assert_equal(get_account_status(usr), AccountStatus.SUSPENDED)
        set_account_status(usr, AccountStatus.ACTIVE)
        assert_equal(get_account_status(usr), AccountStatus.ACTIVE)
        del_account(usr, 'root')


class TestAccountRestApi():

    def test_create_user_success(self):
        """ ACCOUNT (REST): send a POST to create a new user """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

    def test_create_user_failure(self):
        """ ACCOUNT (REST): send a POST with an existing user to test the error case """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        r1 = TestApp(account_app.wsgifunc(*mw)).post('/jdoe', headers=headers, params=data, expect_errors=True)
        r1 = TestApp(account_app.wsgifunc(*mw)).post('/jdoe', headers=headers, params=data, expect_errors=True)

        assert_equal(r1.status, 409)

    def test_create_user_non_json_body(self):
        """ ACCOUNT (REST): send a POST with a non json body"""
        mw = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        token = str(r.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = {'type': 'USER'}
        ret = TestApp(account_app.wsgifunc(*mw)).post('/testuser', headers=headers, params=data, expect_errors=True)

        assert_equal(ret.header('ExceptionClass'), 'ValueError')
        assert_equal(ret.normal_body, '{"ExceptionMessage": "cannot decode json parameter dictionary", "ExceptionClass": "ValueError"}')
        assert_equal(ret.status, 400)

    def test_create_user_missing_parameter(self):
        """ ACCOUNT (REST): send a POST with a missing parameter"""
        mw = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        token = str(r.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({})
        ret = TestApp(account_app.wsgifunc(*mw)).post('/account', headers=headers, params=data, expect_errors=True)

        assert_equal(ret.header('ExceptionClass'), 'KeyError')
        assert_equal(ret.normal_body, '{"ExceptionMessage": "\'type\' not defined", "ExceptionClass": "KeyError"}')
        assert_equal(ret.status, 400)

    def test_create_user_not_json_dict(self):
        """ ACCOUNT (REST): send a POST with a non dictionary json body"""
        mw = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        token = str(r.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = dumps(('account', 'account'))
        r = TestApp(account_app.wsgifunc(*mw)).post('/testaccount', headers=headers, params=data, expect_errors=True)

        assert_equal(r.header('ExceptionClass'), 'TypeError')
        assert_equal(r.normal_body, '{"ExceptionMessage": "body must be a json dictionary", "ExceptionClass": "TypeError"}')
        assert_equal(r.status, 400)

    def test_get_user_success(self):
        """ ACCOUNT (REST): send a GET to retrieve the infos of the new user """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr, headers=headers3, expect_errors=True)
        body = loads(r3.body)
        assert_equal(body['account'], acntusr)
        assert_equal(r3.status, 200)

    def test_get_user_failure(self):
        """ ACCOUNT (REST): send a GET with a wrong user test the error """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': token}
        r2 = TestApp(account_app.wsgifunc(*mw)).get('/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 404)

    def test_del_user_success(self):
        """ ACCOUNT (REST): send a DELETE to disable the new user """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).delete('/' + acntusr, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 200)

        headers4 = {'X-Rucio-Auth-Token': str(token)}
        r4 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr, headers=headers4, expect_errors=True)
        body = loads(r4.body)
        assert_true(body['status'] == AccountStatus.DELETED.description)
        assert_equal(r3.status, 200)

    def test_del_user_failure(self):
        """ ACCOUNT (REST): send a DELETE with a wrong user to test the error """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).delete('/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 404)

    def test_whoami_account(self):
        """ ACCOUNT (REST): Test the whoami method."""
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).get('/whoami', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 303)

    def test_add_attribute(self):
        """ ACCOUNT (REST): add/get/delete attribute."""
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        key = account_name_generator()
        value = "true"
        data = dumps({'key': key, 'value': value})
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/{0}/attr/{1}'.format(acntusr, key), headers=headers2, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

        r4 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr + '/attr/', headers=headers2, expect_errors=True)
        assert_equal(r4.status, 200)

        r5 = TestApp(account_app.wsgifunc(*mw)).delete('/{0}/attr/{1}'.format(acntusr, key), headers=headers2, params=data, expect_errors=True)
        assert_equal(r5.status, 200)


class TestAccountClient():

    def setup(self):
        self.client = AccountClient()

    def test_add_account_success(self):
        """ ACCOUNT (CLIENTS): create a new account and get information about account."""
        account = account_name_generator()
        type, email = 'USER', 'rucio@email.com'
        ret = self.client.add_account(account, type, email)
        assert_true(ret)

        with assert_raises(Duplicate):
            self.client.add_account(account, type, email)

        with assert_raises(InvalidObject):
            self.client.add_account('BAD_ACCOUNT_NAME', type, email)

        with assert_raises(InvalidObject):
            self.client.add_account('toooooooloooooonaccounnnnnnnntnammmmme', type, email)

        acc_info = self.client.get_account(account)
        assert_equal(acc_info['account'], account)

    @raises(AccountNotFound)
    def test_get_account_notfound(self):
        """ ACCOUNT (CLIENTS): try to get information about not existing account."""
        account = str(uuid())
        self.client.get_account(account)

    def test_list_accounts(self):
        """ ACCOUNT (CLIENTS): get list of all accounts."""
        dn = '/C=CH/ST=Geneva/O=CERN/OU=PH-ADP-CO/CN=DDMLAB Client Certificate/emailAddress=ph-adp-ddm-lab@cern.ch'
        acc_list = [account_name_generator() for i in xrange(5)]
        for account in acc_list:
            self.client.add_account(account, 'USER', 'rucio@email.com')

        svr_list = [a['account'] for a in self.client.list_accounts(account_type='SERVICE', identity=dn)]
        assert_true('root' in svr_list)

        svr_list = [a['account'] for a in self.client.list_accounts(account_type='USER')]
        for account in acc_list:
            assert_true(account in svr_list)

    def test_ban_unban_account(self):
        """ ACCOUNT (CLIENTS): create a new account and ban/unban it."""
        account = account_name_generator()
        type, email = 'USER', 'rucio@email.com'
        ret = self.client.add_account(account, type, email)
        assert_true(ret)
        self.client.set_account_status(account=account, status='SUSPENDED')
        status = self.client.get_account(account=account)['status']
        assert_equal(status, 'SUSPENDED')
        self.client.set_account_status(account=account, status='ACTIVE')
        status = self.client.get_account(account=account)['status']
        assert_equal(status, 'ACTIVE')
