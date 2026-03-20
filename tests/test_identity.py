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

import random
import string
from urllib.parse import urlencode

import pytest

from rucio.common.config import config_get_bool
from rucio.common.exception import IdentityError, IdentityNotFound
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account, del_account
from rucio.core.identity import add_account_identity, add_identity, del_account_identity, del_identity, list_identities, verify_identity
from rucio.db.sqla.constants import AccountType, DatabaseOperationType, IdentityType
from rucio.db.sqla.session import db_session
from rucio.tests.common import account_name_generator, auth, hdrdict, headers, rfc2253_dn_generator
from rucio.tests.common_server import get_vo


@pytest.mark.noparallel(reason='adds/removes entities with non-unique names')
class TestIdentity:
    """
    Test the Identity abstraction layer
    """

    def test_userpass(self, random_account):
        """ IDENTITY (CORE): Test adding and removing username/password authentication """

        add_identity(random_account.external, IdentityType.USERPASS, email='ph-adp-ddm-lab@cern.ch', password='secret')
        add_account_identity('ddmlab_%s' % random_account, IdentityType.USERPASS, random_account, email='ph-adp-ddm-lab@cern.ch', password='secret')

        add_identity('/ch/cern/rucio/ddmlab_%s' % random_account, IdentityType.X509, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('/ch/cern/rucio/ddmlab_%s' % random_account, IdentityType.X509, random_account, email='ph-adp-ddm-lab@cern.ch')

        add_identity('ddmlab_%s' % random_account, IdentityType.GSS, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('ddmlab_%s' % random_account, IdentityType.GSS, random_account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('ddmlab_%s' % random_account, IdentityType.USERPASS, random_account)
        del_account_identity('/ch/cern/rucio/ddmlab_%s' % random_account, IdentityType.X509, random_account)
        del_account_identity('ddmlab_%s' % random_account, IdentityType.GSS, random_account)

        del_identity('ddmlab_%s' % random_account, IdentityType.USERPASS)

    def test_ssh(self, random_account):
        """ IDENTITY (CORE): Test adding and removing SSH public key authentication """

        add_identity(random_account.external, IdentityType.SSH, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('my_public_key', IdentityType.SSH, random_account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('my_public_key', IdentityType.SSH, random_account)
        del_identity(random_account.external, IdentityType.SSH)


def test_userpass(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST to add an identity to an account."""
    username = uuid()

    # normal addition
    headers_dict = {'X-Rucio-Username': username, 'X-Rucio-Password': 'secret', 'X-Rucio-Email': 'email'}
    response = rest_client.put('/identities/root/userpass', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 201


def test_verify_userpass_identity():
    """ Test if an identity exists in the db, mapping to at least one account. """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}
    account_name = account_name_generator()
    account = InternalAccount(account_name, **vo)
    username = ''.join(random.choice(string.ascii_letters) for i in range(10))
    email = username + '@email.com'

    with db_session(DatabaseOperationType.WRITE) as session:
        add_account(account, AccountType.USER, email, session=session)

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

    with db_session(DatabaseOperationType.WRITE) as session:
        del_account(account, session=session)


def test_verify_x509_identity():
    """ Test if an x509 identity exists in the db, mapped to at least one account. """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}
    account_name = account_name_generator()
    account = InternalAccount(account_name, **vo)
    dn = rfc2253_dn_generator()
    email = 'doesntmatter@email.com'

    with db_session(DatabaseOperationType.WRITE) as session:
        add_account(account, AccountType.USER, email, session=session)

    add_identity(dn, IdentityType.X509, email=email)
    add_account_identity(dn, IdentityType.X509, account, email=email)

    with pytest.raises(IdentityError):
        verify_identity(f"{dn}/C=fail", IdentityType.X509)

    assert verify_identity(dn, IdentityType.X509) is True

    del_account_identity(dn, IdentityType.X509, account)
    del_identity(dn, IdentityType.X509)
    with db_session(DatabaseOperationType.WRITE) as session:
        del_account(account, session=session)


class TestListAccountsByIdentity:
    """ Test the /identities/accounts endpoint """

    def test_list_accounts_by_identity(self, rest_client, auth_token, random_account):
        """ IDENTITY (REST): Test listing accounts by identity using query parameters """
        identity_key = uuid()
        email = identity_key + '@email.com'

        add_identity(identity_key, IdentityType.USERPASS, email=email, password='secret')
        add_account_identity(identity_key, IdentityType.USERPASS, random_account, email=email, password='secret')

        query_string = urlencode({'identity_key': identity_key, 'type': 'USERPASS'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 200
        accounts = response.get_json()
        assert random_account.external in accounts

        del_account_identity(identity_key, IdentityType.USERPASS, random_account)
        del_identity(identity_key, IdentityType.USERPASS)

    def test_list_accounts_by_identity_oidc_format(self, rest_client, auth_token, random_account):
        """ IDENTITY (REST): Test listing accounts by OIDC identity with slashes in identity_key """
        # OIDC identity format with slashes - use unique identifier to avoid conflicts
        unique_id = random_account.external
        identity_key = f'SUB={unique_id}, ISS=https://auth.example.com/realms/test'
        email = f'{unique_id}@email.com'

        add_identity(identity_key, IdentityType.OIDC, email=email)
        add_account_identity(identity_key, IdentityType.OIDC, random_account, email=email)

        query_string = urlencode({'identity_key': identity_key, 'type': 'OIDC'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 200
        accounts = response.get_json()
        assert random_account.external in accounts

        del_account_identity(identity_key, IdentityType.OIDC, random_account)
        del_identity(identity_key, IdentityType.OIDC)

    def test_list_accounts_by_identity_missing_identity_key(self, rest_client, auth_token):
        """ IDENTITY (REST): Test listing accounts by identity with missing identity_key """
        query_string = urlencode({'type': 'USERPASS'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 400
        assert 'identity_key parameter is required' in response.get_data(as_text=True)

    def test_list_accounts_by_identity_missing_type(self, rest_client, auth_token):
        """ IDENTITY (REST): Test listing accounts by identity with missing type """
        query_string = urlencode({'identity_key': 'test_identity'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 400
        assert 'type parameter is required' in response.get_data(as_text=True)

    def test_list_accounts_by_identity_invalid_type(self, rest_client, auth_token):
        """ IDENTITY (REST): Test listing accounts by identity with invalid type """
        query_string = urlencode({'identity_key': 'test_identity', 'type': 'INVALID_TYPE'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 400
        assert 'Invalid identity type' in response.get_data(as_text=True)
