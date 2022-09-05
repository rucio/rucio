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

import unittest
import random
import string

import pytest

from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account, del_account
from rucio.core.identity import add_identity, del_identity, add_account_identity, del_account_identity, list_identities, verify_identity
from rucio.db.sqla.constants import AccountType, IdentityType
from rucio.tests.common import account_name_generator, headers, hdrdict, auth
from rucio.tests.common_server import get_vo
from rucio.common.exception import IdentityNotFound, IdentityError


@pytest.mark.noparallel(reason='adds/removes entities with non-unique names')
class TestIdentity(unittest.TestCase):
    """
    Test the Identity abstraction layer
    """

    def setUp(self):
        """ Setup the Test Case """
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.account = InternalAccount(account_name_generator(), **self.vo)
        add_account(self.account, AccountType.USER, 'rucio@email.com')

    def tearDown(self):
        """ Tear down the Test Case """
        del_account(self.account)

    def test_userpass(self):
        """ IDENTITY (CORE): Test adding and removing username/password authentication """

        add_identity(self.account.external, IdentityType.USERPASS, email='ph-adp-ddm-lab@cern.ch', password='secret')
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

        add_identity(self.account.external, IdentityType.SSH, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('my_public_key', IdentityType.SSH, self.account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('my_public_key', IdentityType.SSH, self.account)
        del_identity(self.account.external, IdentityType.SSH)


def test_userpass(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST to add an identity to an account."""
    username = uuid()

    # normal addition
    headers_dict = {'X-Rucio-Username': username, 'X-Rucio-Password': 'secret', 'X-Rucio-Email': 'email'}
    response = rest_client.put('/identities/root/userpass', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 201


def test_verify_identity():
    """ Test if an idenity exists in the db, mapping to at least one account. """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}
    account_name = account_name_generator()
    account = InternalAccount(account_name, **vo)
    username = ''.join(random.choice(string.ascii_letters) for i in range(10))
    email = username + '@email.com'

    add_account(account, AccountType.USER, email)

    password = ''.join(random.choice(string.ascii_letters) for i in range(10))
    add_identity(username, IdentityType.USERPASS, email=email, password=password)
    add_account_identity(username, IdentityType.USERPASS, account, email=username + '@email.com', password=password)

    with pytest.raises(IdentityError):
        verify_identity(username, IdentityType.X509, password=password)

    assert verify_identity(username, IdentityType.USERPASS, password=password) is True

    with pytest.raises(IdentityNotFound):
        verify_identity(username, IdentityType.USERPASS, password=password + 'wrong')

    del_account_identity(username, IdentityType.USERPASS, account)
    del_identity(username, IdentityType.USERPASS)
    del_account(account)
