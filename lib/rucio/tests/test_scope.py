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

import json
from uuid import uuid4 as uuid

from paste.fixture import TestApp
from nose.tools import assert_equal, assert_true

from rucio.client.accountclient import AccountClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import AccountNotFound, Duplicate, RucioException, ScopeNotFound
from rucio.core.scope import bulk_add_scopes, get_scopes, add_scope
from rucio.db.session import build_database, create_root_account, destroy_database
from rucio.web.rest.account import app as account_app
from rucio.web.rest.authentication import app as auth_app
from rucio.web.rest.scope import app as scope_app


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
        """ SCOPE (REST): send a PUT to create a new account and scope """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).put('/testaccount', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(scope_app.wsgifunc(*mw)).put('/testaccount/testscope', headers=headers3, expect_errors=True)
        assert_equal(r3.status, 201)

    def test_scope_failure(self):
        """ SCOPE (REST): send a PUT to create a new scope for a not existing account to test the error"""
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        r2 = TestApp(scope_app.wsgifunc(*mw)).put('/testaccount/testscope', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 500)

    def test_list_scope(self):
        """ SCOPE (REST): send a GET list all scopes for one account """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).put('/testaccount', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        for scope in self.scopes:
            r3 = TestApp(scope_app.wsgifunc(*mw)).put('/testaccount/' + scope, headers=headers3, expect_errors=True)
            assert_equal(r3.status, 201)

        r4 = TestApp(scope_app.wsgifunc(*mw)).get('/testaccount', headers=headers3, expect_errors=True)

        assert_equal(r4.status, 200)

        svr_list = json.loads(r4.body)
        for scope in self.scopes:
            if scope not in svr_list:
                assert_true(False)

    def test_list_scope_account_not_found(self):
        """ SCOPE (REST): send a GET list all scopes for a not existing account """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        print r1
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(scope_app.wsgifunc(*mw)).get('/testaccount', headers=headers3, expect_errors=True)

        print r3.body
        assert_equal(r3.status, 500)
        assert_equal(r3.body.split(':')[0], 'AccountNotFound')

    def test_list_scope_no_scopes(self):
        """ SCOPE (REST): send a GET list all scopes for one account without scopes """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        print r1
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(account_app.wsgifunc(*mw)).put('/testaccount', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}

        r4 = TestApp(scope_app.wsgifunc(*mw)).get('/testaccount', headers=headers3, expect_errors=True)

        assert_equal(r4.status, 500)
        assert_equal(r4.body.split(':')[0], 'ScopeNotFound')


class xTestScopeClient():
    def setUp(self):
        creds = {'username': 'ddmlab', 'password': 'secret', 'clientcert': '/opt/rucio/etc/web/client.crt'}
        self.account_client = AccountClient('127.0.0.1', account='root', auth_type='userpass', creds=creds)
        self.scope_client = ScopeClient('127.0.0.1', account='root', auth_type='userpass', creds=creds)

    def tearDown(self):
        pass

    def test_create_scope(self):
        """ SCOPE (CLIENTS): create a new scope."""
        try:
            account = str(uuid())
            scope = str(uuid())
            self.account_client.create_account(account)
            ret = self.scope_client.add_scope(account, scope)
            assert_true(ret)
        except RucioException:
            assert_true(False)

    def test_create_scope_no_account(self):
        """ SCOPE (CLIENTS): try to create scope for not existing account."""
        try:
            account = str(uuid())
            scope = str(uuid())
            self.scope_client.add_scope(account, scope)
        except AccountNotFound:
            assert_true(True)
        else:
            assert_true(False)

    def test_create_scope_duplicate(self):
        """ SCOPE (CLIENTS): try to create a duplicate scope."""
        try:
            account = str(uuid())
            scope = str(uuid())
            self.account_client.create_account(account)
            self.scope_client.add_scope(account, scope)
            self.scope_client.add_scope(account, scope)
        except Duplicate:
            assert_true(True)
        else:
            assert_true(False)

    def test_list_scopes(self):
        """ SCOPE (CLIENTS): try to list scopes for an account."""
        scope_list = [str(uuid()) + str(i) for i in xrange(5)]
        try:
            account = str(uuid())
            self.account_client.create_account(account)
            for scope in scope_list:
                self.scope_client.add_scope(account, scope)

            svr_list = self.scope_client.list_scopes_for_account(account)

            for scope in scope_list:
                if scope not in svr_list:
                    assert_true(False)
        except RucioException:
            assert_true(True)

    def test_list_scopes_account_not_found(self):
        """ SCOPE (CLIENTS): try to list scopes for a non existing account."""
        try:
            account = str(uuid())
            self.scope_client.list_scopes_for_account(account)
        except AccountNotFound:
            assert_true(True)
        else:
            assert_true(False)

    def test_list_scopes_no_scopes(self):
        """ SCOPE (CLIENTS): try to list scopes for an account without scopes."""
        try:
            account = str(uuid())
            self.account_client.create_account(account)
            self.scope_client.list_scopes_for_account(account)
        except ScopeNotFound:
            assert_true(True)
        else:
            assert_true(False)
