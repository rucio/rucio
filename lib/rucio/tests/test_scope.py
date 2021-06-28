# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2013
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import unittest
from json import loads

import pytest

from rucio.client.accountclient import AccountClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.config import config_get_bool
from rucio.common.exception import AccountNotFound, Duplicate, ScopeNotFound, InvalidObject
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.scope import get_scopes, add_scope, is_scope_owner
from rucio.tests.common import account_name_generator, scope_name_generator, headers, auth, hdrdict
from rucio.tests.common_server import get_vo


class TestScopeCoreApi(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.scopes = [InternalScope(scope_name_generator(), **self.vo) for _ in range(5)]
        self.jdoe = InternalAccount('jdoe', **self.vo)

    def test_list_scopes(self):
        """ SCOPE (CORE): List scopes """
        for scope in self.scopes:
            add_scope(scope=scope, account=self.jdoe)
        scopes = get_scopes(account=self.jdoe)
        for scope in scopes:
            assert scope in scopes

    def test_is_scope_owner(self):
        """ SCOPE (CORE): Is scope owner """
        scope = InternalScope(scope_name_generator(), **self.vo)
        add_scope(scope=scope, account=self.jdoe)
        anwser = is_scope_owner(scope=scope, account=self.jdoe)
        assert anwser is True


def test_scope_success(rest_client, auth_token):
    """ SCOPE (REST): send a POST to create a new account and scope """
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio.email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    scopeusr = scope_name_generator()
    response = rest_client.post('/accounts/%s/scopes/%s' % (acntusr, scopeusr), headers=headers(auth(auth_token)))
    assert response.status_code == 201


def test_scope_failure(rest_client, auth_token):
    """ SCOPE (REST): send a POST to create a new scope for a not existing account to test the error"""
    scopeusr = scope_name_generator()
    account_name_generator()
    response = rest_client.post('/accounts/%s/scopes/%s' % (scopeusr, scopeusr), headers=headers(auth(auth_token)))
    assert response.status_code == 404


def test_scope_duplicate(rest_client, auth_token):
    """ SCOPE (REST): send a POST to create a already existing scope to test the error"""
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    scopeusr = scope_name_generator()
    response = rest_client.post('/accounts/%s/scopes/%s' % (acntusr, scopeusr), headers=headers(auth(auth_token)))
    assert response.status_code == 201
    response = rest_client.post('/accounts/%s/scopes/%s' % (acntusr, scopeusr), headers=headers(auth(auth_token)))
    assert response.status_code == 409


def test_list_scope(rest_client, auth_token):
    """ SCOPE (REST): send a GET list all scopes for one account """
    tmp_val = account_name_generator()
    headers_dict = {'Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/%s' % tmp_val, headers=headers(auth(auth_token), hdrdict(headers_dict)), json=data)
    assert response.status_code == 201

    scopes = [scope_name_generator() for _ in range(5)]
    for scope in scopes:
        response = rest_client.post('/accounts/%s/scopes/%s' % (tmp_val, scope), headers=headers(auth(auth_token)), json={})
        assert response.status_code == 201

    response = rest_client.get('/accounts/%s/scopes/' % tmp_val, headers=headers(auth(auth_token)))
    assert response.status_code == 200

    svr_list = loads(response.get_data(as_text=True))
    for scope in scopes:
        assert scope in svr_list


def test_list_scope_account_not_found(rest_client, auth_token):
    """ SCOPE (REST): send a GET list all scopes for a not existing account """
    response = rest_client.get('/accounts/testaccount/scopes/', headers=headers(auth(auth_token)))
    assert response.status_code == 404
    assert response.headers.get('ExceptionClass') == 'AccountNotFound'


def test_list_scope_no_scopes(rest_client, auth_token):
    """ SCOPE (REST): send a GET list all scopes for one account without scopes """
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}

    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/accounts/%s/scopes/' % acntusr, headers=headers(auth(auth_token)))
    assert response.status_code == 404
    assert response.headers.get('ExceptionClass') == 'ScopeNotFound'


class TestScopeClient(unittest.TestCase):

    def setUp(self):
        self.account_client = AccountClient()
        self.scope_client = ScopeClient()

    def test_create_scope(self):
        """ SCOPE (CLIENTS): create a new scope."""
        account = 'jdoe'
        scope = scope_name_generator()
        ret = self.scope_client.add_scope(account, scope)
        assert ret
        with pytest.raises(InvalidObject):
            self.scope_client.add_scope(account, 'tooooolooooongscooooooooooooope')
        with pytest.raises(InvalidObject):
            self.scope_client.add_scope(account, '$?!')

    def test_create_scope_no_account(self):
        """ SCOPE (CLIENTS): try to create scope for not existing account."""
        account = str(uuid()).lower()[:30]
        scope = scope_name_generator()
        with pytest.raises(AccountNotFound):
            self.scope_client.add_scope(account, scope)

    def test_create_scope_duplicate(self):
        """ SCOPE (CLIENTS): try to create a duplicate scope."""
        account = 'jdoe'
        scope = scope_name_generator()
        self.scope_client.add_scope(account, scope)
        with pytest.raises(Duplicate):
            self.scope_client.add_scope(account, scope)

    def test_list_scopes(self):
        """ SCOPE (CLIENTS): try to list scopes for an account."""
        account = 'jdoe'
        scope_list = [scope_name_generator() for _ in range(5)]
        for scope in scope_list:
            self.scope_client.add_scope(account, scope)

        svr_list = self.scope_client.list_scopes_for_account(account)

        for scope in scope_list:
            if scope not in svr_list:
                assert False

    def test_list_scopes_account_not_found(self):
        """ SCOPE (CLIENTS): try to list scopes for a non existing account."""
        account = account_name_generator()
        with pytest.raises(AccountNotFound):
            self.scope_client.list_scopes_for_account(account)

    def test_list_scopes_no_scopes(self):
        """ SCOPE (CLIENTS): try to list scopes for an account without scopes."""
        account = account_name_generator()
        self.account_client.add_account(account, 'USER', 'rucio@email.com')
        with pytest.raises(ScopeNotFound):
            self.scope_client.list_scopes_for_account(account)
