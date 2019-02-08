# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012, 2017
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2015
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019

"""
Test the Identity abstraction layer
"""

from nose.tools import assert_equal
from paste.fixture import TestApp

from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account, del_account
from rucio.core.identity import add_identity, del_identity, add_account_identity, del_account_identity, list_identities
from rucio.db.sqla.constants import AccountType, IdentityType
from rucio.tests.common import account_name_generator
from rucio.web.rest.identity import APP as identity_app
from rucio.web.rest.authentication import APP as auth_app


class TestIdentity(object):
    """
    Test the Identity abstraction layer
    """

    def setup(self):
        """ Setup the Test Case """
        self.account = account_name_generator()
        add_account(self.account, AccountType.USER, 'rucio@email.com')

    def tearDown(self):
        """ Tear down the Test Case """
        del_account(self.account)

    def test_userpass(self):
        """ IDENTITY (CORE): Test adding and removing username/password authentication """

        add_identity(self.account, IdentityType.USERPASS, email='ph-adp-ddm-lab@cern.ch', password='secret')
        add_account_identity('ddmlab_%s' % self.account, IdentityType.USERPASS, self.account, email='ph-adp-ddm-lab@cern.ch', password='secret')

        add_identity('/ch/cern/rucio/ddmlab_%s' % self.account, IdentityType.X509, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('/ch/cern/rucio/ddmlab_%s' % self.account, IdentityType.X509, self.account, email='ph-adp-ddm-lab@cern.ch')

        add_identity('ddmlab_%s' % self.account, IdentityType.GSS, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('ddmlab_%s' % self.account, IdentityType.GSS, self.account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('ddmlab_%s' % self.account, IdentityType.USERPASS, self.account)
        del_account_identity('/ch/cern/rucio/ddmlab_%s' % self.account, IdentityType.X509, self.account)
        del_account_identity('ddmlab_%s' % self.account, IdentityType.GSS, self.account)

        del_identity('ddmlab_%s' % self.account, IdentityType.USERPASS)

    def test_ssh(self):
        """ IDENTITY (CORE): Test adding and removing SSH public key authentication """

        add_identity(self.account, IdentityType.SSH, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('my_public_key', IdentityType.SSH, self.account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('my_public_key', IdentityType.SSH, self.account)
        del_identity(self.account, IdentityType.SSH)


class TestIdentityRest(object):
    def test_userpass(self):
        """ ACCOUNT (REST): send a POST to add an identity to an account."""
        mw = []
        account = 'root'
        headers1 = {'X-Rucio-Account': account, 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))
        username = uuid()
        password = 'secret'

        # normal addition
        headers2 = {'X-Rucio-Auth-Token': str(token), 'X-Rucio-Username': username, 'X-Rucio-Password': password,
                    'X-Rucio-Email': 'email'}
        res2 = TestApp(identity_app.wsgifunc(*mw)).put('/' + account + '/userpass', headers=headers2, expect_errors=True)
        assert_equal(res2.status, 201)
