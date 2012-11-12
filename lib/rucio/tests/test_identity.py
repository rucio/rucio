# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from uuid import uuid4 as uuid

from rucio.core.account import add_account
from rucio.core.identity import add_identity, del_identity, add_account_identity,\
    del_account_identity, list_identities


class TestIdentity():

    def setUp(self):
        self.account = str(uuid())
        add_account(self.account, 'user')

    def tearDown(self):
        pass

    def test_userpass(self):
        """ IDENTITY (CORE): Test adding and removing username/password authentication """

        add_identity(self.account, 'userpass', password='secret')
        add_account_identity('ddmlab_%s' % self.account, 'userpass', self.account)

        add_identity('/ch/cern/rucio/ddmlab_%s' % self.account, 'x509')
        add_account_identity('/ch/cern/rucio/ddmlab_%s' % self.account, 'x509', self.account)

        add_identity('ddmlab_%s' % self.account, 'gss')
        add_account_identity('ddmlab_%s' % self.account, 'gss', self.account)

        list_identities()

        del_account_identity('ddmlab_%s' % self.account, 'userpass', self.account)
        del_account_identity('/ch/cern/rucio/ddmlab_%s' % self.account, 'x509', self.account)
        del_account_identity('ddmlab_%s' % self.account, 'gss', self.account)

        del_identity('ddmlab_%s' % self.account, 'userpass')
