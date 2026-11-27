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

import datetime
import time
from base64 import b64decode

import pytest
from paramiko import Message

from rucio.common.exception import CannotAuthenticate, Duplicate
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid, ssh_sign
from rucio.core.authentication import strip_x509_proxy_attributes
from rucio.core.identity import add_account_identity, del_account_identity
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.gateway.authentication import get_auth_token_ssh, get_auth_token_user_pass, get_ssh_challenge_token
from rucio.tests.common import hdrdict, headers, loginhdr, vohdr

PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq5LySllrQFpPL"\
             "614sulXQ7wnIr1aGhGtl8b+HCB/0FhMSMTHwSjX78UbfqEorZ"\
             "V16rXrWPgUpvcbp2hqctw6eCbxwqcgu3uGWaeS5A0iWRw7oXU"\
             "h6ydnVy89zGzX1FJFFDZ+AgiZ3ytp55tg1bjqqhK1OSC0pJxd"\
             "Ne878TRVVo5MLI0S/rZY2UovCSGFaQG2iLj14wz/YqI7NFMUu"\
             "JFR4e6xmNsOP7fCZ4bGMsmnhR0GmY0dWYTupNiP5WdYXAfKEx"\
             "lnvFLTlDI5Mgh4Z11NraQ8pv4YE1woolYpqOc/IMMBBXFniTT"\
             "4tC7cgikxWb9ZmFe+r4t6yCDpX4IL8L5GOQ== test_comment"

INVALID_PADDED_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq5LySllrQFpPL"\
    "614sulXQ7wnIr1aGhGtl8b+HCB/0FhMSMTHwSjX78UbfqEorZ"\
    "V16rXrWPgUpvcbp2hqctw6eCbxwqcgu3uGWaeS5A0iWRw7oXU"\
    "h6ydnVy89zGzX1FJFFDZ+AgiZ3ytp55tg1bjqqhK1OSC0pJxd"\
    "Ne878TRVVo5MLI0S/rZY2UovCSGFaQG2iLj14wz/YqI7NFMUu"\
    "JFR4e6xmNsOP7fCZ4bGMsmnhR0GmY0dWYTupNiP5WdYXAfKEx"\
    "lnvFLTlDI5Mgh4Z11NraQ8pv4YE1woolYpqOc/IMMBBXFniTT"\
    "4tC7cgikxWb9ZmFe+r4t6yCDpX4IL8L5GOQ test_comment"  # padding removed

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAq5LySllrQFpPL614sulXQ7wnIr1aGhGtl8b+HCB/0FhMSMTH
wSjX78UbfqEorZV16rXrWPgUpvcbp2hqctw6eCbxwqcgu3uGWaeS5A0iWRw7oXUh
6ydnVy89zGzX1FJFFDZ+AgiZ3ytp55tg1bjqqhK1OSC0pJxdNe878TRVVo5MLI0S
/rZY2UovCSGFaQG2iLj14wz/YqI7NFMUuJFR4e6xmNsOP7fCZ4bGMsmnhR0GmY0d
WYTupNiP5WdYXAfKExlnvFLTlDI5Mgh4Z11NraQ8pv4YE1woolYpqOc/IMMBBXFn
iTT4tC7cgikxWb9ZmFe+r4t6yCDpX4IL8L5GOQIBIwKCAQBObw+s9a1fPzokbI7y
s9Ae9u1RtaWIQph/5fCB4viZwfb8sbpm7hmSLjh0Zu4GNbI/aRshW3cnwWu6PlyM
R2svnMZKWwemKdcEadzABgESyxPyCakbCrLmBvet6J0t3HdZsoK/Gd/w/edFTlgn
L/Y/Hn67B6MJbA1ae/4lHzz0XY5qpmDNkMYvIWdUdpXnX6QIY23ZqLiHz1HlpI1K
fGBWjGj2p61p8iUc30+mP9wjDUFxUlE9koLfVp93tOA4KRVUkJdKpKeSFulJODu8
FL+bfdil3d4vNWTxsr4AHpyf9VKj+RzlvUuz4NZGdCLGsj10QEINIi1rgg5q9Dqx
Ay9LAoGBAOP0x4yfY93T4t3DOWVUw4NCovTI9maED8SGGJ6r00ee7GVrAHHFlZBt
tazaBXRYTbmNO74TxeTSX0Z1wfU9Q2krxttGwoMyWNhRzm/76SunmRAPtrnnZvC7
WkMdcTVTNj5xuZxVaxvLAHQh639rp3D5mzNpyBseo0CwYaaLYfgfAoGBAMCueZKd
pcl+Tj89JLgqHPxzvIDN9YU1fPOH4oD5zfeFryaSS9EiYIDKqJsdGIGgIk3kbU2P
DouJ68yZybij6oI+VkGCSCHSR0KQDwXABr7h5+KscggksGsWRObrMxMvpB3NBtv9
O8dPspOmH6XbcgIwb/rJCJxOUSklKiUCJVanAoGAVKtgD6jqlDjB+pj4D7HE9j1S
eC1i1Z7EByp+LE5zC/kzO5zFppnYd3k02c1Se6vFGQiSiG2+iDDhjzMNhvl/cDTU
1RpIP1vX21GV0dKYb0zhFJgfTF1Dffxx+6vZl3atv2wRvblTqzzFp3pQKANqFATw
gM+E1t9+dxzxEflBpU0CgYB+nopnqWzyH80E/EtUc3IiPW0+szrxIyY5onBGIIAJ
DrTtdhSQvtGzuGArauQ37ONXwf6vT2FUYfK5puOlOIQps++KImnqVvugxREvqhMP
uQYYnTT+CXs/DqJOmo9HH06XPZbLFB/4ASw1JAYrKc6TuW4odXqv27GtUu/PLUu8
mQKBgQDTinWi2THxJhzYloxupcgW0kI+htxOr5QcXUxIPh4zc7lsHyzZ4IqNISaa
AYkc9cZ+tulIOvu5mTS6OwfMIv8ql5j4xjyrCEYs9zG1vc+0IB5r0tea2unn+bxE
VPEtp2ruk2N7rv0DixwcEQlD/DqsfmR2/QWDeDd1xxoTXPhIXQ==
-----END RSA PRIVATE KEY-----"""


@pytest.mark.parametrize('dn, stripped_dn', [
    ('', ''),
    ('/DC=com/DC=example/OU=Users/CN=John Doe', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=123456789/CN=John Doe', '/DC=com/DC=example/OU=Users/CN=123456789/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=John Doe/CN=limited proxy', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=John Doe/CN=proxy', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=John Doe/CN=123456789', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=John Doe/CN=limited proxy/CN=123456789', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=John Doe/CN=proxy/CN=123456789', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('/DC=com/DC=example/OU=Users/CN=John Doe/CN=123456789/CN=123456789', '/DC=com/DC=example/OU=Users/CN=John Doe'),
    ('CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
    ('CN=John Doe,CN=123456789,OU=Users,DC=example,DC=com', 'CN=John Doe,CN=123456789,OU=Users,DC=example,DC=com'),
    ('CN=limited proxy,CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
    ('CN=proxy,CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
    ('CN=123456789,CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
    ('CN=123456789,CN=limited proxy,CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
    ('CN=123456789,CN=proxy,CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
    ('CN=123456789,CN=123456789,CN=John Doe,OU=Users,DC=example,DC=com', 'CN=John Doe,OU=Users,DC=example,DC=com'),
])
def test_strip_x509_proxy_attributes(vo, dn, stripped_dn):
    """ AUTHENTICATION (CORE): Test the stripping of X509-proxy attributes"""
    assert strip_x509_proxy_attributes(dn) == stripped_dn


def test_ssh_sign_uses_rsa_sha2_256():
    """AUTHENTICATION (COMMON): ssh_sign must sign with rsa-sha2-256, not the removed ssh-rsa (SHA-1)."""
    signature = ssh_sign(PRIVATE_KEY, 'challenge-0123456789abcdef')
    # the algorithm name is the first field of the signature blob
    algorithm = Message(b64decode(signature)).get_text()
    assert algorithm == 'rsa-sha2-256'


@pytest.mark.noparallel(reason='changes identities of the same account')
class TestAuthCoreGateway:
    """
    TestAuthCoreGateway
    """

    def test_get_auth_token_user_pass_success(self, vo):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='secret', appid='test', ip='127.0.0.1', vo=vo)
        assert result is not None

    def test_get_auth_token_user_pass_fail(self, vo):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='not_secret', appid='test', ip='127.0.0.1', vo=vo)
        assert result is None

    def test_get_auth_token_ssh_success(self, vo, root_account):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (good signature)."""

        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        challenge_token = get_ssh_challenge_token(account='root', appid='test', ip='127.0.0.1', vo=vo).get('token')

        signature = ssh_sign(PRIVATE_KEY, challenge_token)

        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1', vo=vo)

        assert result is not None

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account)

    def test_get_auth_token_ssh_fail(self, vo, root_account):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (wrong signature)."""

        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        signature = ssh_sign(PRIVATE_KEY, 'sign_something_else')

        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1', vo=vo)

        assert result is None

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account)

    def test_invalid_padding(self, vo, root_account):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (public key with invalid padding)."""

        try:
            add_account_identity(INVALID_PADDED_PUBLIC_KEY, IdentityType.SSH, root_account, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        challenge_token = get_ssh_challenge_token(account='root', appid='test', ip='127.0.0.1', vo=vo).get('token')

        signature = ssh_sign(PRIVATE_KEY, challenge_token)
        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1', vo=vo)
        assert result is not None

        del_account_identity(INVALID_PADDED_PUBLIC_KEY, IdentityType.SSH, root_account)


def test_userpass_fail(vo, rest_client):
    """AUTHENTICATION (REST): Username and password (wrong credentials)."""
    response = rest_client.get('/auth/userpass', headers=headers(loginhdr('wrong', 'wrong', 'wrong'), vohdr(vo)))
    assert response.status_code == 401


def test_userpass_success(vo, rest_client):
    """AUTHENTICATION (REST): Username and password (correct credentials)."""
    response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(vo)))
    assert response.status_code == 200
    assert len(response.headers.get('X-Rucio-Auth-Token')) > 32


@pytest.mark.noparallel(reason='changes identities of the same account')
def test_ssh_success(vo, rest_client, root_account):
    """AUTHENTICATION (REST): SSH RSA public key exchange (correct credentials)."""

    try:
        add_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account, email='ph-adp-ddm-lab@cern.ch')
    except Duplicate:
        pass  # might already exist, can skip

    headers_dict = {'X-Rucio-Account': 'root'}
    response = rest_client.get('/auth/ssh_challenge_token', headers=headers(hdrdict(headers_dict), vohdr(vo)))
    assert response.status_code == 200
    assert 'challenge-' in response.headers.get('X-Rucio-SSH-Challenge-Token')

    signature = ssh_sign(PRIVATE_KEY, response.headers.get('X-Rucio-SSH-Challenge-Token'))

    headers_dict = {'X-Rucio-Account': 'root', 'X-Rucio-SSH-Signature': signature}
    response = rest_client.get('/auth/ssh', headers=headers(hdrdict(headers_dict), vohdr(vo)))
    assert response.status_code == 200
    assert len(response.headers.get('X-Rucio-Auth-Token')) > 32

    del_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account)


@pytest.mark.noparallel(reason='changes identities of the same account')
def test_ssh_fail(vo, rest_client, root_account):
    """AUTHENTICATION (REST): SSH RSA public key exchange (wrong credentials)."""

    try:
        add_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account, email='ph-adp-ddm-lab@cern.ch')
    except Duplicate:
        pass  # might already exist, can skip

    signature = ssh_sign(PRIVATE_KEY, 'sign_something_else')

    headers_dict = {'X-Rucio-Account': 'root', 'X-Rucio-SSH-Signature': signature}
    response = rest_client.get('/auth/ssh', headers=headers(hdrdict(headers_dict), vohdr(vo)))
    assert response.status_code == 401

    del_account_identity(PUBLIC_KEY, IdentityType.SSH, root_account)


@pytest.mark.noparallel(reason='adds many tokens')
def test_many_tokens(vo, root_account, db_session):
    """AUTHENTICATION (REST): Error when deleting too many tokens."""
    for i in range(2000):
        models.Token(account=root_account, token="dummytoken" + str(i), ip='127.0.0.1', expired_at=datetime.datetime.utcnow()).save(session=db_session)
    db_session.commit()

    # Ensures that the tokens are expired
    time.sleep(1)
    print(get_auth_token_user_pass(account='root', username='ddmlab', password='secret', appid='test', ip='127.0.0.1', vo=vo))


def test_non_jwt_validation():
    """ AUTHENTICATION: passing a fake X-Rucio-Auth-Token that looks like a JWT """
    from rucio.gateway.authentication import validate_auth_token
    with pytest.raises(CannotAuthenticate):
        validate_auth_token('a.b.c')


@pytest.mark.noparallel(reason='adds and removes tokens shared between accounts')
class TestTokenAccountSelection:
    """
    One OIDC access token authenticates an identity, and that identity can be
    mapped to several accounts, so the same token can be registered for more
    than one of them. These tests cover that the account the client asks for is
    the account the token is validated for.
    """

    @staticmethod
    def _register(token: str, account: InternalAccount, session) -> None:
        models.Token(account=account, token=token, identity='SUB=test_sub, ISS=https://test_issuer/',
                     ip='127.0.0.1',
                     expired_at=datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)).save(session=session)

    def test_same_token_resolves_per_requested_account(self, random_account_factory, db_session):
        """AUTHENTICATION (CORE): the requested account decides which registration of a token is used."""
        from rucio.core.authentication import validate_auth_token

        first, second = random_account_factory(), random_account_factory()
        token = 'multi-account-token-' + generate_uuid()
        self._register(token, first, db_session)
        self._register(token, second, db_session)
        db_session.commit()

        # Asking for either account returns that account, not whichever
        # registration happens to come first out of the database. The two calls
        # also have to resolve differently despite sharing the token cache.
        assert validate_auth_token(token, first.external, session=db_session)['account'] == first
        assert validate_auth_token(token, second.external, session=db_session)['account'] == second

    def test_token_rejected_for_unregistered_account(self, random_account_factory, db_session):
        """AUTHENTICATION (CORE): a token is not valid for an account it is not registered for."""
        from rucio.core.authentication import validate_auth_token

        registered, other = random_account_factory(), random_account_factory()
        token = 'single-account-token-' + generate_uuid()
        self._register(token, registered, db_session)
        db_session.commit()

        assert validate_auth_token(token, registered.external, session=db_session)['account'] == registered
        with pytest.raises(CannotAuthenticate):
            validate_auth_token(token, other.external, session=db_session)

    def test_expired_token_cleanup_keeps_other_accounts(self, random_account_factory, db_session):
        """AUTHENTICATION (CORE): expiring one account's tokens leaves another account's registration of the same token."""
        from rucio.core.authentication import get_auth_token_user_pass, validate_auth_token

        kept = random_account_factory()
        token = 'shared-expired-token-' + generate_uuid()

        # One expired registration for root, one still valid for another account.
        models.Token(account=InternalAccount('root', vo=kept.vo), token=token,
                     ip='127.0.0.1', expired_at=datetime.datetime.utcnow()).save(session=db_session)
        self._register(token, kept, db_session)
        db_session.commit()

        # Authenticating as root triggers the cleanup of root's expired tokens.
        get_auth_token_user_pass(account=InternalAccount('root', vo=kept.vo), username='ddmlab',
                                 password='secret', appid='test', ip='127.0.0.1', session=db_session)
        db_session.commit()

        assert validate_auth_token(token, kept.external, session=db_session)['account'] == kept

    def test_requested_account_resolves_without_a_vo(self, random_account_factory, db_session):
        """AUTHENTICATION (CORE): the account name is matched without the caller supplying a VO."""
        from rucio.core.authentication import validate_auth_token

        account = random_account_factory()
        token = 'no-vo-supplied-token-' + generate_uuid()
        self._register(token, account, db_session)
        db_session.commit()

        # Only the external name is passed, exactly as the X-Rucio-Account
        # header carries it. Under a non-default VO the account's internal name
        # is "<name>@<vo>", so matching must not assume the default VO.
        resolved = validate_auth_token(token, account.external, session=db_session)
        assert resolved['account'] == account
        assert resolved['account'].vo == account.vo


def test_rest_honours_requested_account(vo, rest_client, random_account):
    """AUTHENTICATION (REST): a token is not accepted for an account it was not issued for."""
    response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(vo)))
    assert response.status_code == 200
    token = response.headers.get('X-Rucio-Auth-Token')

    # The token was issued for root, so root is accepted ...
    response = rest_client.get('/accounts/root', headers=headers(
        hdrdict({'X-Rucio-Auth-Token': token, 'X-Rucio-Account': 'root'}), vohdr(vo)))
    assert response.status_code == 200

    # ... and an account it was not issued for is not silently used instead.
    response = rest_client.get('/accounts/root', headers=headers(
        hdrdict({'X-Rucio-Auth-Token': token, 'X-Rucio-Account': random_account.external}), vohdr(vo)))
    assert response.status_code == 401
