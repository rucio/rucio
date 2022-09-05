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

from rucio.api.account import add_account, account_exists, del_account, update_account, get_account_info
from rucio.common.config import config_get
from rucio.common.exception import AccountNotFound, Duplicate, InvalidObject
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import list_identities, add_account_attribute, list_account_attributes, del_account_attribute
from rucio.core.identity import add_account_identity, add_identity
from rucio.db.sqla.constants import AccountStatus, IdentityType
from rucio.tests.common import account_name_generator, headers, auth, vohdr, loginhdr


class TestAccountCoreApi:

    def test_create_and_check_for_user(self, vo):
        """ ACCOUNT (CORE): Test the creation, query, and deletion of an account """
        usr = account_name_generator()
        invalid_usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root', vo=vo)
        assert account_exists(usr, vo=vo)
        assert not account_exists(invalid_usr, vo=vo)
        del_account(usr, 'root', vo=vo)

    def test_update_account(self, vo):
        """ ACCOUNT (CORE): Test changing and quering account parameters """
        usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root', vo=vo)
        assert get_account_info(usr, vo=vo)['status'] == AccountStatus.ACTIVE  # Should be active by default
        update_account(account=usr, key='status', value=AccountStatus.SUSPENDED, vo=vo)
        assert get_account_info(usr, vo=vo)['status'] == AccountStatus.SUSPENDED
        update_account(account=usr, key='status', value=AccountStatus.ACTIVE, vo=vo)
        assert get_account_info(usr, vo=vo)['status'] == AccountStatus.ACTIVE
        update_account(account=usr, key='email', value='test', vo=vo)
        email = get_account_info(account=usr, vo=vo)['email']
        assert email == 'test'
        del_account(usr, 'root', vo=vo)

    def test_list_account_identities(self, vo):
        """ ACCOUNT (CORE): Test listing of account identities """
        email = 'email'
        identity = uuid()
        identity_type = IdentityType.USERPASS
        account = InternalAccount('root', vo=vo)
        add_account_identity(identity, identity_type, account, email, password='secret')
        identities = list_identities(account)
        assert {'type': identity_type, 'identity': identity, 'email': email} in identities

    def test_add_account_attribute(self, vo):
        """ ACCOUNT (CORE): Test adding attribute to account """
        account = InternalAccount('root', vo=vo)
        key = account_name_generator()
        value = True
        add_account_attribute(account, key, value)
        assert {'key': key, 'value': True} in list_account_attributes(account)
        with pytest.raises(Duplicate):
            add_account_attribute(account, key, value)


def test_create_user_success(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST to create a new user """
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201


def test_create_user_failure(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST with an existing user to test the error case """
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/jdoe', headers=headers(auth(auth_token)), json=data)
    assert response.status_code in (201, 409)
    response = rest_client.post('/accounts/jdoe', headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 409


def test_create_user_non_json_body(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST with a non json body"""
    response = rest_client.post('/accounts/testuser', headers=headers(auth(auth_token)), data="unfug")
    assert response.status_code == 400
    assert response.headers.get('ExceptionClass') == 'ValueError'
    assert loads(response.get_data(as_text=True)) == {"ExceptionMessage": "cannot decode json parameter dictionary", "ExceptionClass": "ValueError"}


def test_create_user_missing_parameter(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST with a missing parameter"""
    response = rest_client.post('/accounts/account', headers=headers(auth(auth_token)), json={})
    assert response.status_code == 400
    assert response.headers.get('ExceptionClass') == 'KeyError'
    assert loads(response.get_data(as_text=True)) == {"ExceptionMessage": "\'type\' not defined", "ExceptionClass": "KeyError"}


def test_create_user_not_json_dict(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST with a non dictionary json body"""
    data = ('account', 'account')
    response = rest_client.post('/accounts/testaccount', headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 400
    assert response.headers.get('ExceptionClass') == 'TypeError'
    assert loads(response.get_data(as_text=True)) == {"ExceptionMessage": "body must be a json dictionary", "ExceptionClass": "TypeError"}


def test_get_user_success(rest_client, auth_token):
    """ ACCOUNT (REST): send a GET to retrieve the infos of the new user """
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/accounts/' + acntusr, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    body = loads(response.get_data(as_text=True))
    assert body['account'] == acntusr


def test_get_user_failure(rest_client, auth_token):
    """ ACCOUNT (REST): send a GET with a wrong user test the error """
    reponse = rest_client.get('/accounts/wronguser', headers=headers(auth(auth_token)))
    assert reponse.status_code == 404


def test_del_user_success(rest_client, auth_token):
    """ ACCOUNT (REST): send a DELETE to disable the new user """
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.delete('/accounts/' + acntusr, headers=headers(auth(auth_token)))
    assert response.status_code == 200

    response = rest_client.get('/accounts/' + acntusr, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    body = loads(response.get_data(as_text=True))
    assert body['status'] == AccountStatus.DELETED.name


def test_del_user_failure(rest_client, auth_token):
    """ ACCOUNT (REST): send a DELETE with a wrong user to test the error """
    response = rest_client.delete('/accounts/wronguser', headers=headers(auth(auth_token)))
    assert response.status_code == 404


def test_whoami_account(rest_client, auth_token):
    """ ACCOUNT (REST): Test the whoami method."""
    response = rest_client.get('/accounts/whoami', headers=headers(auth(auth_token)))
    assert response.status_code == 303


def test_add_attribute(rest_client, auth_token):
    """ ACCOUNT (REST): add/get/delete attribute."""
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    key = account_name_generator()
    value = "true"
    data = {'key': key, 'value': value}
    response = rest_client.post('/accounts/{0}/attr/{1}'.format(acntusr, key), headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/accounts/' + acntusr + '/attr/', headers=headers(auth(auth_token)))
    assert response.status_code == 200

    response = rest_client.delete('/accounts/{0}/attr/{1}'.format(acntusr, key), headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 200


def test_update_account(rest_client, auth_token):
    """ ACCOUNT (REST): send a PUT to update an account."""
    acntusr = account_name_generator()
    data = {'type': 'USER', 'email': 'rucio@email.com'}
    response = rest_client.post('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    data = {'status': 'SUSPENDED', 'email': 'test'}
    response = rest_client.put('/accounts/' + acntusr, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 200

    response = rest_client.get('/accounts/' + acntusr, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    body = loads(response.get_data(as_text=True))
    assert body['status'] == 'SUSPENDED'
    assert body['email'] == 'test'


def test_delete_identity_of_account(vo, rest_client):
    """ ACCOUNT (REST): send a DELETE to remove an identity of an account."""
    account = account_name_generator()
    identity = uuid()
    password = 'secret'
    add_account(account, 'USER', 'rucio@email.com', 'root', vo=vo)
    add_identity(identity, IdentityType.USERPASS, 'email@email.com', password)
    add_account_identity(identity, IdentityType.USERPASS, InternalAccount(account, vo=vo), 'email@email.com')
    auth_response = rest_client.get('/auth/userpass', headers=headers(loginhdr(account, identity, password), vohdr(vo)))
    assert auth_response.status_code == 200
    assert 'X-Rucio-Auth-Token' in auth_response.headers
    token = str(auth_response.headers.get('X-Rucio-Auth-Token'))
    assert len(token) != 0

    # normal deletion
    data = {'authtype': 'USERPASS', 'identity': identity}
    internal_account = InternalAccount(account, vo=vo)
    add_account_attribute(internal_account, 'account_admin', True)
    response = rest_client.delete('/accounts/' + account + '/identities', headers=headers(auth(token)), json=data)
    assert response.status_code == 200

    # unauthorized deletion
    other_account = account_name_generator()
    del_account_attribute(internal_account, 'account_admin')
    data = {'authtype': 'USERPASS', 'identity': identity}
    response = rest_client.delete('/accounts/' + other_account + '/identities', headers=headers(auth(token)), json=data)
    assert response.status_code == 401


def test_add_identity_to_account(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST to add an identity to an account."""
    identity = uuid()

    # normal addition
    data = {'authtype': 'USERPASS', 'email': 'rucio@email.com', 'password': 'password', 'identity': identity}
    response = rest_client.post('/accounts/root/identities', headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    # duplicate identity
    response = rest_client.post('/accounts/root/identities', headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 409

    # missing password
    identity = uuid()
    data = {'authtype': 'USERPASS', 'email': 'rucio@email.com', 'identity': identity}
    response = rest_client.post('/accounts/root/identities', headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 400


class TestAccountClient:

    def test_add_account_success(self, account_client):
        """ ACCOUNT (CLIENTS): create a new account and get information about account."""
        account = account_name_generator()
        type_, email = 'USER', 'rucio@email.com'
        ret = account_client.add_account(account, type_, email)
        assert ret

        with pytest.raises(Duplicate):
            account_client.add_account(account, type_, email)

        with pytest.raises(InvalidObject):
            account_client.add_account('BAD_ACCOUNT_NAME', type_, email)

        with pytest.raises(InvalidObject):
            account_client.add_account('toooooooloooooonaccounnnnnnnntnammmmme', type_, email)

        acc_info = account_client.get_account(account)
        assert acc_info['account'] == account

    def test_get_account_notfound(self, account_client):
        """ ACCOUNT (CLIENTS): try to get information about not existing account."""
        account = str(uuid())
        with pytest.raises(AccountNotFound):
            account_client.get_account(account)

    def test_list_accounts(self, account_client):
        """ ACCOUNT (CLIENTS): get list of all accounts."""
        dn = config_get('bootstrap', 'x509_identity')
        acc_list = [account_name_generator() for _ in range(5)]
        for account in acc_list:
            account_client.add_account(account, 'USER', 'rucio@email.com')

        svr_list = [a['account'] for a in account_client.list_accounts(account_type='SERVICE', identity=dn)]
        assert 'root' in svr_list

        svr_list = [a['account'] for a in account_client.list_accounts(account_type='USER')]
        for account in acc_list:
            assert account in svr_list

    def test_update_account(self, account_client):
        """ ACCOUNT (CLIENTS): create a new account and update it."""
        account = account_name_generator()
        type_, email = 'USER', 'rucio@email.com'
        ret = account_client.add_account(account, type_, email)
        assert ret
        account_client.update_account(account=account, key='status', value='SUSPENDED')
        status = account_client.get_account(account=account)['status']
        assert status == 'SUSPENDED'
        account_client.update_account(account=account, key='status', value='ACTIVE')
        status = account_client.get_account(account=account)['status']
        assert status == 'ACTIVE'
        account_client.update_account(account=account, key='email', value='test')
        email = account_client.get_account(account=account)['email']
        assert email == 'test'
