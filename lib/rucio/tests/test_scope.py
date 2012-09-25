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
from nose.tools import assert_equal, assert_true, assert_list_equal, raises

from rucio.client.accountclient import AccountClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import AccountNotFound, Duplicate, ScopeNotFound
from rucio.common.utils import generate_uuid as uuid
from rucio.core.scope import get_scopes, add_scope
from rucio.db.session import build_database, create_root_account, destroy_database
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app


class TestScopeCoreApi():

    @classmethod
    def setUpClass(cls):
        build_database(echo=False)
        create_root_account()

    @classmethod
    def tearDownClass(cls):
        destroy_database(echo=False)

    def setUp(self):
        self.scopes = ['test_scope_' + str(uuid()) for i in range(5)]

    def test_list_scopes(self):
        """ SCOPE (CORE): List scopes """
        for scope in self.scopes:
            add_scope(scope=scope, account='root')
        scopes = get_scopes(account='root')
        assert_list_equal(self.scopes, scopes)


class TestScope():

    @classmethod
    def setUpClass(cls):
        build_database(echo=False)
        create_root_account()

    @classmethod
    def tearDownClass(cls):
        destroy_database(echo=False)

    def setUp(self):
        self.scopes = ['test_scope_' + str(i) for i in range(5)]

    def test_scope_success(self):
        """ SCOPE (REST): send a POST to create a new account and scope """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        acntusr = 'user' + str(uuid())
        data = dumps({'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        scopeusr = 'testscope' + str(uuid())
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes/' + scopeusr, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 201)

    def test_scope_failure(self):
        """ SCOPE (REST): send a POST to create a new scope for a not existing account to test the error"""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))
        headers2 = {'Rucio-Auth-Token': str(token)}
        scopeusr = 'testscope' + str(uuid())
        acntusr = 'user' + str(uuid())
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/%(scopeusr)s/scopes/%(scopeusr)s' % locals(), headers=headers2, expect_errors=True)
        assert_equal(r2.status, 404)

    def test_scope_duplicate(self):
        """ SCOPE (REST): send a POST to create a already existing scope to test the error"""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Auth-Token': str(token)}
        acntusr = 'user' + str(uuid())
        data = dumps({'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        scopeusr = 'testscope' + str(uuid())
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes/' + scopeusr, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 201)
        r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes/' + scopeusr, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 409)

    def test_list_scope(self):
        """ SCOPE (REST): send a GET list all scopes for one account """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        data = dumps({'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        for scope in self.scopes:
            data = dumps({})
            r3 = TestApp(account_app.wsgifunc(*mw)).post('/testaccount/scopes/' + scope, headers=headers3, params=data, expect_errors=True)
            assert_equal(r3.status, 201)

        r4 = TestApp(account_app.wsgifunc(*mw)).get('/testaccount/scopes/', headers=headers3, expect_errors=True)

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
        acntusr = 'user' + str(uuid())
        data = dumps({'accountType': 'user'})
        r2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}

        r4 = TestApp(account_app.wsgifunc(*mw)).get('/%(acntusr)s/scopes/' % locals(), headers=headers3, params=data, expect_errors=True)

        assert_equal(r4.status, 404)
        assert_equal(r4.header('ExceptionClass'), 'ScopeNotFound')


class TestScopeClient():

    @classmethod
    def setUpClass(cls):
        build_database(echo=False)
        create_root_account()

    @classmethod
    def tearDownClass(cls):
        destroy_database(echo=False)

    def setUp(self):
        self.account_client = AccountClient()
        self.scope_client = ScopeClient()

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
