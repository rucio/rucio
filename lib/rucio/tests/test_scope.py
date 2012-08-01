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

from json import dumps, loads

from paste.fixture import TestApp
from nose.tools import assert_equal, assert_true, raises

from rucio.client.accountclient import AccountClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import AccountNotFound, Duplicate, ScopeNotFound
from rucio.common.utils import generate_uuid as uuid
from rucio.core.scope import bulk_add_scopes, get_scopes, add_scope
from rucio.db.session import build_database, create_root_account, destroy_database
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app


class TestScopeCoreApi():

    def setUp(self):
        build_database()
        create_root_account()
        self.scopes = ['test_scope_' + str(uuid()) for i in range(5)]

    def tearDown(self):
        destroy_database()

    def test_bulk_add_scopes(self):
        """ SCOPE (CORE): bulk create multiple scopes """

        bulk_add_scopes(self.scopes, 'root', skipExisting=True)

    def test_list_scopes(self):
        """ SCOPE (CORE): List scopes """

        for scope in self.scopes:
            add_scope(scope=scope, account='root')

        scopes = get_scopes(account='root')
        assert_equal(self.scopes, scopes)


class TestScope():

    def setUp(self):
        build_database()
        create_root_account()
        self.scopes = ['test_scope_' + str(i) for i in range(5)]

    def tearDown(self):
        destroy_database()

    def test_scope_success(self):
        """ SCOPE (REST): send a POST to create a new account and scope """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testaccount', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'scopeName': 'testscope'})
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

    def test_scope_failure(self):
        """ SCOPE (REST): send a POST to create a new scope for a not existing account to test the error"""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'scopeName': 'testscope'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 404)

    def test_scope_duplicate(self):
        """ SCOPE (REST): send a POST to create a already existing scope to test the error"""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testaccount', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        data = dumps({'scopeName': 'testscope'})
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 201)
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 409)

    def test_add_scope_non_json_body(self):
        """ SCOPE (REST): send a POST with a non json body"""
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

    def test_add_scope_missing_parameter(self):
        """ SCOPE (REST): send a POST with a missing parameter"""
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

    def test_scope_user_not_json_dict(self):
        """ SCOPE (REST): send a POST with a non dictionary json body"""
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

    def test_list_scope(self):
        """ SCOPE (REST): send a GET list all scopes for one account """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testaccount', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        for scope in self.scopes:
            data = dumps({'scopeName': scope})
            r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes', headers=headers3, params=data, expect_errors=True)
            assert_equal(r3.status, 201)

        r4 = TestApp(account_app.wsgifunc(*mw)).get('/testaccount/scopes', headers=headers3, expect_errors=True)

        assert_equal(r4.status, 200)

        svr_list = loads(r4.body)
        for scope in self.scopes:
            if scope not in svr_list:
                assert_true(False)

    def test_list_scope_account_not_found(self):
        """ SCOPE (REST): send a GET list all scopes for a not existing account """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(account_app.wsgifunc(*mw)).get('/testaccount/scopes', headers=headers3, expect_errors=True)

        assert_equal(r3.status, 404)
        assert_equal(r3.header('ExceptionClass'), 'AccountNotFound')

    def test_list_scope_no_scopes(self):
        """ SCOPE (REST): send a GET list all scopes for one account without scopes """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Auth-Token': str(token)}
        data = dumps({'accountName': 'testaccount', 'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}

        r4 = TestApp(account_app.wsgifunc(*mw)).get('/testaccount/scopes', headers=headers3, params=data, expect_errors=True)

        assert_equal(r4.status, 404)
        assert_equal(r4.header('ExceptionClass'), 'ScopeNotFound')


class xTestScopeClient():
    def setUp(self):
        creds = {'username': 'ddmlab', 'password': 'secret'}
        self.account_client = AccountClient(rucio_host='localhost', auth_host='localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)
        self.scope_client = ScopeClient(rucio_host='localhost', auth_host='localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

    def tearDown(self):
        pass

    def test_create_scope(self):
        """ SCOPE (CLIENTS): create a new scope."""
        account = str(uuid())
        scope = str(uuid())
        self.account_client.create_account(account, 'user')
        ret = self.scope_client.add_scope(account, scope)
        assert_true(ret)

    @raises(AccountNotFound)
    def test_create_scope_no_account(self):
        """ SCOPE (CLIENTS): try to create scope for not existing account."""
        account = str(uuid())
        scope = str(uuid())
        self.scope_client.add_scope(account, scope)

    @raises(Duplicate)
    def test_create_scope_duplicate(self):
        """ SCOPE (CLIENTS): try to create a duplicate scope."""
        account = str(uuid())
        scope = str(uuid())
        self.account_client.create_account(account, 'user')
        self.scope_client.add_scope(account, scope)
        self.scope_client.add_scope(account, scope)

    def test_list_scopes(self):
        """ SCOPE (CLIENTS): try to list scopes for an account."""
        scope_list = [str(uuid()) + str(i) for i in xrange(5)]
        account = str(uuid())
        self.account_client.create_account(account, 'user')
        for scope in scope_list:
            self.scope_client.add_scope(account, scope)

        svr_list = self.scope_client.list_scopes_for_account(account)

        for scope in scope_list:
            if scope not in svr_list:
                assert_true(False)

    @raises(AccountNotFound)
    def test_list_scopes_account_not_found(self):
        """ SCOPE (CLIENTS): try to list scopes for a non existing account."""
        account = str(uuid())
        self.scope_client.list_scopes_for_account(account)

    @raises(ScopeNotFound)
    def test_list_scopes_no_scopes(self):
        """ SCOPE (CLIENTS): try to list scopes for an account without scopes."""
        account = str(uuid())
        self.account_client.create_account(account, 'user')
        self.scope_client.list_scopes_for_account(account)
