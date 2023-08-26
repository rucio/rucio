# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from json import loads

import pytest

from rucio.common.exception import AccountNotFound, Duplicate, ScopeNotFound, InvalidObject
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.scope import get_scopes, add_scope, is_scope_owner
from rucio.tests.common import account_name_generator, scope_name_generator, headers, auth, hdrdict


class TestScopeCoreApi:

    def test_list_scopes(self, vo, jdoe_account):
        scopes = [InternalScope(scope_name_generator(), vo=vo) for _ in range(5)]
        """ SCOPE (CORE): List scopes """
        for scope in scopes:
            add_scope(scope=scope, account=jdoe_account)
        scopes = get_scopes(account=jdoe_account)
        for scope in scopes:
            assert scope in scopes

    def test_is_scope_owner(self, vo, jdoe_account):
        """ SCOPE (CORE): Is scope owner """
        scope = InternalScope(scope_name_generator(), vo=vo)
        add_scope(scope=scope, account=jdoe_account)
        anwser = is_scope_owner(scope=scope, account=jdoe_account)
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


class TestScopeClient:

    def test_create_scope(self, rucio_client):
        """ SCOPE (CLIENTS): create a new scope."""
        account = 'jdoe'
        scope = scope_name_generator()
        ret = rucio_client.add_scope(account, scope)
        assert ret
        with pytest.raises(InvalidObject):
            rucio_client.add_scope(account, 'tooooolooooongscooooooooooooope')
        with pytest.raises(InvalidObject):
            rucio_client.add_scope(account, '$?!')

    def test_create_scope_no_account(self, rucio_client):
        """ SCOPE (CLIENTS): try to create scope for not existing account."""
        account = str(uuid()).lower()[:30]
        scope = scope_name_generator()
        with pytest.raises(AccountNotFound):
            rucio_client.add_scope(account, scope)

    def test_create_scope_duplicate(self, rucio_client):
        """ SCOPE (CLIENTS): try to create a duplicate scope."""
        account = 'jdoe'
        scope = scope_name_generator()
        rucio_client.add_scope(account, scope)
        with pytest.raises(Duplicate):
            rucio_client.add_scope(account, scope)

    def test_list_scopes(self, rucio_client):
        """ SCOPE (CLIENTS): try to list scopes for an account."""
        account = 'jdoe'
        scope_list = [scope_name_generator() for _ in range(5)]
        for scope in scope_list:
            rucio_client.add_scope(account, scope)

        svr_list = rucio_client.list_scopes_for_account(account)

        for scope in scope_list:
            if scope not in svr_list:
                assert False

    def test_list_scopes_account_not_found(self, rucio_client):
        """ SCOPE (CLIENTS): try to list scopes for a non existing account."""
        account = account_name_generator()
        with pytest.raises(AccountNotFound):
            rucio_client.list_scopes_for_account(account)

    def test_list_scopes_no_scopes(self, rucio_client):
        """ SCOPE (CLIENTS): try to list scopes for an account without scopes."""
        account = account_name_generator()
        rucio_client.add_account(account, 'USER', 'rucio@email.com')
        with pytest.raises(ScopeNotFound):
            rucio_client.list_scopes_for_account(account)
