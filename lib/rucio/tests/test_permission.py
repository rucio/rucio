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

import pytest
import unittest

from rucio.api.permission import has_permission
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.scope import add_scope
from rucio.core.account import add_account_attribute, del_account_attribute
from rucio.tests.common import scope_name_generator
from rucio.tests.common_server import get_vo


class TestPermissionCoreApi(unittest.TestCase):
    """
    Test the Permission Core and API
    """

    def setUp(self):
        """ Setup Test Case """
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.usr = 'jdoe'

    def tearDown(self):
        """ Tear down Test Case """
        pass

    def test_permission_add_did(self):
        """ PERMISSION(CORE): Check permission to add a did"""
        scope = scope_name_generator()
        add_scope(scope=InternalScope(scope, **self.vo), account=InternalAccount('root', **self.vo))
        assert has_permission(issuer='panda', action='add_did', kwargs={'scope': scope}, **self.vo)
        assert not has_permission(issuer='spock', action='add_did', kwargs={'scope': scope}, **self.vo)

    def test_permission_add_account(self):
        """ PERMISSION(CORE): Check permission to add account """
        assert has_permission(issuer='root', action='add_account', kwargs={'account': 'account1'}, **self.vo)
        assert not has_permission(issuer='self.usr', action='add_account', kwargs={'account': 'account1'}, **self.vo)

    @pytest.mark.noparallel(reason='Add/delete account attribute of an existing account')
    def test_permission_add_scope(self):
        """ PERMISSION(CORE): Check permission to add scope """
        assert has_permission(issuer='root', action='add_scope', kwargs={'account': 'account1'}, **self.vo)
        assert not has_permission(issuer=self.usr, action='add_scope', kwargs={'account': 'root'}, **self.vo)
        add_account_attribute(InternalAccount(self.usr, **self.vo), 'scope_admin', True)
        assert has_permission(issuer=self.usr, action='add_scope', kwargs={'account': self.usr}, **self.vo)
        del_account_attribute(InternalAccount(self.usr, **self.vo), 'scope_admin')

    def test_permission_get_auth_token_user_pass(self):
        """ PERMISSION(CORE): Check permission to get_auth_token_user_pass """
        assert has_permission(issuer='root', action='get_auth_token_user_pass', kwargs={'account': 'root', 'username': 'ddmlab', 'password': 'secret'}, **self.vo)
        assert not has_permission(issuer='root', action='get_auth_token_user_pass', kwargs={'account': self.usr, 'username': 'ddmlab', 'password': 'secret'}, **self.vo)

    def test_permission_get_auth_token_x509(self):
        """ PERMISSION(CORE): Check permission to get_auth_token_x509 """
        dn = config_get('bootstrap', 'x509_identity')
        assert has_permission(issuer='root', action='get_auth_token_x509', kwargs={'account': 'root', 'dn': dn}, **self.vo)
        assert not has_permission(issuer='root', action='get_auth_token_x509', kwargs={'account': self.usr, 'dn': dn}, **self.vo)

    def test_permission_get_auth_token_gss(self):
        """ PERMISSION(CORE): Check permission to get_auth_token_gss """
        gsscred = 'rucio-dev@CERN.CH'
        assert has_permission(issuer='root', action='get_auth_token_gss', kwargs={'account': 'root', 'gsscred': gsscred}, **self.vo)
        assert not has_permission(issuer='root', action='get_auth_token_gss', kwargs={'account': self.usr, 'gsscred': gsscred}, **self.vo)

    def test_permission_update_rule_boost(self):
        kwargs = {'options': {'boost_rule': True}}
        assert has_permission(issuer='root', action='update_rule', kwargs=kwargs, **self.vo)
        assert not has_permission(issuer='jdoe', action='update_rule', kwargs=kwargs, **self.vo)
