# Copyright 2012-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019

"""
Test the Permission Core and API
"""

from nose.tools import assert_true, assert_false

from rucio.api.permission import has_permission
from rucio.common.config import config_get
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.scope import add_scope
from rucio.tests.common import scope_name_generator


class TestPermissionCoreApi(object):
    """
    Test the Permission Core and API
    """

    def setup(self):
        """ Setup Test Case """
        self.usr = 'jdoe'

    def tearDown(self):
        """ Tear down Test Case """
        pass

    def test_permission_add_did(self):
        """ PERMISSION(CORE): Check permission to add a did"""
        scope = scope_name_generator()
        add_scope(scope=InternalScope(scope), account=InternalAccount('root'))
        assert_true(has_permission(issuer='panda', action='add_did', kwargs={'scope': scope}))
        assert_false(has_permission(issuer='spock', action='add_did', kwargs={'scope': scope}))

    def test_permission_add_account(self):
        """ PERMISSION(CORE): Check permission to add account """
        assert_true(has_permission(issuer='root', action='add_account', kwargs={'account': 'account1'}))
        assert_false(has_permission(issuer='self.usr', action='add_account', kwargs={'account': 'account1'}))

    def test_permission_add_scope(self):
        """ PERMISSION(CORE): Check permission to add scope """
        assert_true(has_permission(issuer='root', action='add_scope', kwargs={'account': 'account1'}))
        assert_false(has_permission(issuer=self.usr, action='add_scope', kwargs={'account': 'root'}))
        assert_true(has_permission(issuer=self.usr, action='add_scope', kwargs={'account': self.usr}))

    def test_permission_get_auth_token_user_pass(self):
        """ PERMISSION(CORE): Check permission to get_auth_token_user_pass """
        assert_true(has_permission(issuer='root', action='get_auth_token_user_pass', kwargs={'account': 'root', 'username': 'ddmlab', 'password': 'secret'}))
        assert_false(has_permission(issuer='root', action='get_auth_token_user_pass', kwargs={'account': self.usr, 'username': 'ddmlab', 'password': 'secret'}))

    def test_permission_get_auth_token_x509(self):
        """ PERMISSION(CORE): Check permission to get_auth_token_x509 """
        dn = config_get('bootstrap', 'x509_identity')
        assert_true(has_permission(issuer='root', action='get_auth_token_x509', kwargs={'account': 'root', 'dn': dn}))
        assert_false(has_permission(issuer='root', action='get_auth_token_x509', kwargs={'account': self.usr, 'dn': dn}))

    def test_permission_get_auth_token_gss(self):
        """ PERMISSION(CORE): Check permission to get_auth_token_gss """
        gsscred = 'rucio-dev@CERN.CH'
        assert_true(has_permission(issuer='root', action='get_auth_token_gss', kwargs={'account': 'root', 'gsscred': gsscred}))
        assert_false(has_permission(issuer='root', action='get_auth_token_gss', kwargs={'account': self.usr, 'gsscred': gsscred}))
