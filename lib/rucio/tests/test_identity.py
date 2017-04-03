# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2015

"""
Test the Identity abstraction layer
"""

from rucio.core.account import add_account, del_account
from rucio.core.identity import add_identity, del_identity, add_account_identity, del_account_identity, list_identities
from rucio.db.sqla.constants import AccountType, IdentityType
from rucio.tests.common import account_name_generator


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
        add_account_identity('ddmlab_%s' % self.account, IdentityType.USERPASS, self.account, email='ph-adp-ddm-lab@cern.ch')

        add_identity('/ch/cern/rucio/ddmlab_%s' % self.account, IdentityType.X509, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('/ch/cern/rucio/ddmlab_%s' % self.account, IdentityType.X509, self.account, email='ph-adp-ddm-lab@cern.ch')

        add_identity('ddmlab_%s' % self.account, IdentityType.GSS, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('ddmlab_%s' % self.account, IdentityType.GSS, self.account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('ddmlab_%s' % self.account, IdentityType.USERPASS, self.account)
        del_account_identity('/ch/cern/rucio/ddmlab_%s' % self.account, IdentityType.X509, self.account)
        del_account_identity('ddmlab_%s' % self.account, IdentityType.GSS, self.account)

        del_identity('ddmlab_%s' % self.account, IdentityType.USERPASS)
