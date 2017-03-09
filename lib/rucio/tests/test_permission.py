# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

"""
Test the Permission Core and API
"""

from nose.tools import assert_true, assert_false

from rucio.api.permission import has_permission
from rucio.common.config import config_get
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
        add_scope(scope=scope, account='root')
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
        gsscred = 'ddmlab@CERN.CH'
        assert_true(has_permission(issuer='root', action='get_auth_token_gss', kwargs={'account': 'root', 'gsscred': gsscred}))
        assert_false(has_permission(issuer='root', action='get_auth_token_gss', kwargs={'account': self.usr, 'gsscred': gsscred}))
