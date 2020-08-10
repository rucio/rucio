# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2013
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2015-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015-2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

import unittest
from json import dumps, loads

import pytest
from paste.fixture import TestApp

from rucio.api.account import add_account, account_exists, del_account, update_account, get_account_info
from rucio.client.accountclient import AccountClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import AccountNotFound, Duplicate, InvalidObject
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import list_identities, add_account_attribute, list_account_attributes
from rucio.core.identity import add_account_identity, add_identity
from rucio.db.sqla.constants import AccountStatus, IdentityType
from rucio.tests.common import account_name_generator
from rucio.web.rest.account import APP as account_app
from rucio.web.rest.authentication import APP as auth_app


class TestAccountCoreApi(unittest.TestCase):
    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

    def test_create_and_check_for_user(self):
        """ ACCOUNT (CORE): Test the creation, query, and deletion of an account """
        usr = account_name_generator()
        invalid_usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root', **self.vo)
        assert account_exists(usr, **self.vo)
        assert not account_exists(invalid_usr, **self.vo)
        del_account(usr, 'root', **self.vo)

    def test_update_account(self):
        """ ACCOUNT (CORE): Test changing and quering account parameters """
        usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root', **self.vo)
        assert get_account_info(usr, **self.vo)['status'] == AccountStatus.ACTIVE  # Should be active by default
        update_account(account=usr, key='status', value=AccountStatus.SUSPENDED, **self.vo)
        assert get_account_info(usr, **self.vo)['status'] == AccountStatus.SUSPENDED
        update_account(account=usr, key='status', value=AccountStatus.ACTIVE, **self.vo)
        assert get_account_info(usr, **self.vo)['status'] == AccountStatus.ACTIVE
        update_account(account=usr, key='email', value='test', **self.vo)
        email = get_account_info(account=usr, **self.vo)['email']
        assert email == 'test'
        del_account(usr, 'root', **self.vo)

    def test_list_account_identities(self):
        """ ACCOUNT (CORE): Test listing of account identities """
        email = 'email'
        identity = uuid()
        identity_type = IdentityType.USERPASS
        account = InternalAccount('root', **self.vo)
        add_account_identity(identity, identity_type, account, email, password='secret')
        identities = list_identities(account)
        assert {'type': identity_type, 'identity': identity, 'email': email} in identities

    def test_add_account_attribute(self):
        """ ACCOUNT (CORE): Test adding attribute to account """
        account = InternalAccount('root', **self.vo)
        key = account_name_generator()
        value = True
        add_account_attribute(account, key, value)
        assert {'key': key, 'value': True} in list_account_attributes(account)
        with pytest.raises(Duplicate):
            add_account_attribute(account, key, value)


class TestAccountRestApi(unittest.TestCase):
    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            self.vo_header = {'X-Rucio-VO': self.vo['vo']}
        else:
            self.vo = {}
            self.vo_header = {}

    def test_create_user_success(self):
        """ ACCOUNT (REST): send a POST to create a new user """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        res2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert res2.status == 201

    def test_create_user_failure(self):
        """ ACCOUNT (REST): send a POST with an existing user to test the error case """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        res1 = TestApp(account_app.wsgifunc(*mw)).post('/jdoe', headers=headers, params=data, expect_errors=True)
        res1 = TestApp(account_app.wsgifunc(*mw)).post('/jdoe', headers=headers, params=data, expect_errors=True)

        assert res1.status == 409

    def test_create_user_non_json_body(self):
        """ ACCOUNT (REST): send a POST with a non json body"""
        mw = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers.update(self.vo_header)
        res = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert res.status == 200
        token = str(res.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = {'type': 'USER'}
        ret = TestApp(account_app.wsgifunc(*mw)).post('/testuser', headers=headers, params=data, expect_errors=True)

        assert ret.header('ExceptionClass') == 'ValueError'
        assert loads(ret.normal_body.decode()) == {"ExceptionMessage": "cannot decode json parameter dictionary", "ExceptionClass": "ValueError"}
        assert ret.status == 400

    def test_create_user_missing_parameter(self):
        """ ACCOUNT (REST): send a POST with a missing parameter"""
        mw = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers.update(self.vo_header)
        res = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert res.status == 200
        token = str(res.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({})
        ret = TestApp(account_app.wsgifunc(*mw)).post('/account', headers=headers, params=data, expect_errors=True)

        assert ret.header('ExceptionClass') == 'KeyError'
        assert loads(ret.normal_body.decode()) == {"ExceptionMessage": "\'type\' not defined", "ExceptionClass": "KeyError"}
        assert ret.status == 400

    def test_create_user_not_json_dict(self):
        """ ACCOUNT (REST): send a POST with a non dictionary json body"""
        mw = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers.update(self.vo_header)
        res = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert res.status == 200
        token = str(res.header('X-Rucio-Auth-Token'))

        headers = {'X-Rucio-Auth-Token': str(token)}
        data = dumps(('account', 'account'))
        res = TestApp(account_app.wsgifunc(*mw)).post('/testaccount', headers=headers, params=data, expect_errors=True)

        assert res.header('ExceptionClass') == 'TypeError'
        assert loads(res.normal_body.decode()) == {"ExceptionMessage": "body must be a json dictionary", "ExceptionClass": "TypeError"}
        assert res.status == 400

    def test_get_user_success(self):
        """ ACCOUNT (REST): send a GET to retrieve the infos of the new user """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        res2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert res2.status == 201

        headers3 = {'X-Rucio-Auth-Token': str(token)}
        res3 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr, headers=headers3, expect_errors=True)
        body = loads(res3.body.decode())
        assert body['account'] == acntusr
        assert res3.status == 200

    def test_get_user_failure(self):
        """ ACCOUNT (REST): send a GET with a wrong user test the error """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': token}
        res2 = TestApp(account_app.wsgifunc(*mw)).get('/wronguser', headers=headers2, expect_errors=True)
        assert res2.status == 404

    def test_del_user_success(self):
        """ ACCOUNT (REST): send a DELETE to disable the new user """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        res2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert res2.status == 201

        headers3 = {'X-Rucio-Auth-Token': str(token)}
        res3 = TestApp(account_app.wsgifunc(*mw)).delete('/' + acntusr, headers=headers3, expect_errors=True)
        assert res3.status == 200

        headers4 = {'X-Rucio-Auth-Token': str(token)}
        res4 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr, headers=headers4, expect_errors=True)
        body = loads(res4.body.decode())
        assert body['status'] == AccountStatus.DELETED.description  # pylint: disable=no-member
        assert res3.status == 200

    def test_del_user_failure(self):
        """ ACCOUNT (REST): send a DELETE with a wrong user to test the error """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(account_app.wsgifunc(*mw)).delete('/wronguser', headers=headers2, expect_errors=True)
        assert res2.status == 404

    def test_whoami_account(self):
        """ ACCOUNT (REST): Test the whoami method."""
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(account_app.wsgifunc(*mw)).get('/whoami', headers=headers2, expect_errors=True)
        assert res2.status == 303

    def test_add_attribute(self):
        """ ACCOUNT (REST): add/get/delete attribute."""
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        res2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert res2.status == 201

        key = account_name_generator()
        value = "true"
        data = dumps({'key': key, 'value': value})
        res3 = TestApp(account_app.wsgifunc(*mw)).post('/{0}/attr/{1}'.format(acntusr, key), headers=headers2, params=data, expect_errors=True)
        assert res3.status == 201

        res4 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr + '/attr/', headers=headers2, expect_errors=True)
        assert res4.status == 200

        res5 = TestApp(account_app.wsgifunc(*mw)).delete('/{0}/attr/{1}'.format(acntusr, key), headers=headers2, params=data, expect_errors=True)
        assert res5.status == 200

    def test_update_account(self):
        """ ACCOUNT (REST): send a PUT to update an account."""
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))

        acntusr = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'type': 'USER', 'email': 'rucio@email.com'})
        res2 = TestApp(account_app.wsgifunc(*mw)).post('/' + acntusr, headers=headers2, params=data, expect_errors=True)
        assert res2.status == 201

        data = dumps({'status': 'SUSPENDED', 'email': 'test'})
        headers3 = {'X-Rucio-Auth-Token': str(token)}
        res3 = TestApp(account_app.wsgifunc(*mw)).put('/' + acntusr, headers=headers3, params=data, expect_errors=True)
        assert res3.status == 200

        headers4 = {'X-Rucio-Auth-Token': str(token)}
        res4 = TestApp(account_app.wsgifunc(*mw)).get('/' + acntusr, headers=headers4, expect_errors=True)
        body = loads(res4.body.decode())
        assert body['status'] == 'SUSPENDED'
        assert body['email'] == 'test'
        assert res4.status == 200

    def test_delete_identity_of_account(self):
        """ ACCOUNT (REST): send a DELETE to remove an identity of an account."""
        mw = []
        account = account_name_generator()
        identity = uuid()
        password = 'secret'
        add_account(account, 'USER', 'rucio@email.com', 'root', **self.vo)
        add_identity(identity, IdentityType.USERPASS, 'email@email.com', password)
        add_account_identity(identity, IdentityType.USERPASS, InternalAccount(account, **self.vo), 'email@email.com')
        headers1 = {'X-Rucio-Account': account, 'X-Rucio-Username': identity, 'X-Rucio-Password': password}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(res1.header('X-Rucio-Auth-Token'))

        # normal deletion
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'authtype': 'USERPASS', 'identity': identity})
        res2 = TestApp(account_app.wsgifunc(*mw)).delete('/' + account + '/identities', headers=headers2, params=data, expect_errors=True)
        assert res2.status == 200

        # unauthorized deletion
        other_account = account_name_generator()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'authtype': 'USERPASS', 'identity': identity})
        res2 = TestApp(account_app.wsgifunc(*mw)).delete('/' + other_account + '/identities', headers=headers2, params=data, expect_errors=True)
        assert res2.status == 401

    def test_add_identity_to_account(self):
        """ ACCOUNT (REST): send a POST to add an identity to an account."""
        mw = []
        account = 'root'
        headers1 = {'X-Rucio-Account': account, 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert res1.status == 200
        token = str(res1.header('X-Rucio-Auth-Token'))
        identity = uuid()

        # normal addition
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'authtype': 'USERPASS', 'email': 'rucio@email.com', 'password': 'password', 'identity': identity})
        res2 = TestApp(account_app.wsgifunc(*mw)).post('/' + account + '/identities', headers=headers2, params=data, expect_errors=True)
        assert res2.status == 201

        # duplicate identity
        res4 = TestApp(account_app.wsgifunc(*mw)).post('/' + account + '/identities', headers=headers2, params=data, expect_errors=True)
        assert res4.status == 409

        # missing password
        identity = uuid()
        data = dumps({'authtype': 'USERPASS', 'email': 'rucio@email.com', 'identity': identity})
        res3 = TestApp(account_app.wsgifunc(*mw)).post('/' + account + '/identities', headers=headers2, params=data, expect_errors=True)
        assert res3.status == 400


class TestAccountClient(unittest.TestCase):

    def setUp(self):
        self.client = AccountClient()

    def test_add_account_success(self):
        """ ACCOUNT (CLIENTS): create a new account and get information about account."""
        account = account_name_generator()
        type, email = 'USER', 'rucio@email.com'
        ret = self.client.add_account(account, type, email)
        assert ret

        with pytest.raises(Duplicate):
            self.client.add_account(account, type, email)

        with pytest.raises(InvalidObject):
            self.client.add_account('BAD_ACCOUNT_NAME', type, email)

        with pytest.raises(InvalidObject):
            self.client.add_account('toooooooloooooonaccounnnnnnnntnammmmme', type, email)

        acc_info = self.client.get_account(account)
        assert acc_info['account'] == account

    def test_get_account_notfound(self):
        """ ACCOUNT (CLIENTS): try to get information about not existing account."""
        account = str(uuid())
        with pytest.raises(AccountNotFound):
            self.client.get_account(account)

    def test_list_accounts(self):
        """ ACCOUNT (CLIENTS): get list of all accounts."""
        dn = config_get('bootstrap', 'x509_identity')
        acc_list = [account_name_generator() for _ in range(5)]
        for account in acc_list:
            self.client.add_account(account, 'USER', 'rucio@email.com')

        svr_list = [a['account'] for a in self.client.list_accounts(account_type='SERVICE', identity=dn)]
        assert 'root' in svr_list

        svr_list = [a['account'] for a in self.client.list_accounts(account_type='USER')]
        for account in acc_list:
            assert account in svr_list

    def test_update_account(self):
        """ ACCOUNT (CLIENTS): create a new account and update it."""
        account = account_name_generator()
        type, email = 'USER', 'rucio@email.com'
        ret = self.client.add_account(account, type, email)
        assert ret
        self.client.update_account(account=account, key='status', value='SUSPENDED')
        status = self.client.get_account(account=account)['status']
        assert status == 'SUSPENDED'
        self.client.update_account(account=account, key='status', value='ACTIVE')
        status = self.client.get_account(account=account)['status']
        assert status == 'ACTIVE'
        self.client.update_account(account=account, key='email', value='test')
        email = self.client.get_account(account=account)['email']
        assert email == 'test'
