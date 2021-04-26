# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Rahul Chauhan <omrahulchauhan@gmail.com>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import base64
import unittest

import pytest
from requests import session

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_ssh, get_ssh_challenge_token, \
    get_auth_token_saml
from rucio.common.config import config_get_bool
from rucio.common.exception import Duplicate, AccessDenied
from rucio.common.types import InternalAccount
from rucio.common.utils import ssh_sign
from rucio.core.identity import add_account_identity, del_account_identity
from rucio.db.sqla.constants import IdentityType
from rucio.tests.common import headers, hdrdict, loginhdr, vohdr
from rucio.tests.common_server import get_vo

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


@pytest.mark.noparallel(reason='changes identities of the same account')
class TestAuthCoreApi(unittest.TestCase):
    '''
    TestAuthCoreApi
    '''

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

    def test_get_auth_token_user_pass_success(self):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='secret', appid='test', ip='127.0.0.1', **self.vo)
        assert result is not None

    def test_get_auth_token_user_pass_fail(self):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='not_secret', appid='test', ip='127.0.0.1', **self.vo)
        assert result is None

    def test_get_auth_token_ssh_success(self):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (good signature)."""

        root = InternalAccount('root', **self.vo)
        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, root, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        challenge_token = get_ssh_challenge_token(account='root', appid='test', ip='127.0.0.1', **self.vo).get('token')

        signature = base64.b64decode(ssh_sign(PRIVATE_KEY, challenge_token))

        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1', **self.vo)

        assert result is not None

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, root)

    def test_get_auth_token_ssh_fail(self):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (wrong signature)."""

        root = InternalAccount('root', **self.vo)
        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, root, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        signature = ssh_sign(PRIVATE_KEY, 'sign_something_else')

        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1', **self.vo)

        assert result is None

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, root)

    def test_invalid_padding(self):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (public key with invalid padding)."""

        root = InternalAccount('root', **self.vo)
        try:
            add_account_identity(INVALID_PADDED_PUBLIC_KEY, IdentityType.SSH, root, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        challenge_token = get_ssh_challenge_token(account='root', appid='test', ip='127.0.0.1', **self.vo).get('token')

        ssh_sign_string = ssh_sign(PRIVATE_KEY, challenge_token)
        signature = base64.b64decode(ssh_sign_string)
        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1', **self.vo)
        assert result is not None

        del_account_identity(INVALID_PADDED_PUBLIC_KEY, IdentityType.SSH, root)

    def test_get_auth_token_saml_success(self):
        """AUTHENTICATION (CORE): SAML NameID (correct credentials)."""
        root = InternalAccount('root', **self.vo)
        try:
            add_account_identity('ddmlab', IdentityType.SAML, root, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        result = get_auth_token_saml(account='root', saml_nameid='ddmlab', appid='test', ip='127.0.0.1', **self.vo)
        assert result is not None

        del_account_identity('ddmlab', IdentityType.SAML, root)

    def test_get_auth_token_saml_fail(self):
        """AUTHENTICATION (CORE): SAML NameID (wrong credentials)."""
        root = InternalAccount('root', **self.vo)
        try:
            add_account_identity('ddmlab', IdentityType.SAML, root, email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        with pytest.raises(AccessDenied):
            get_auth_token_saml(account='root', saml_nameid='not_ddmlab', appid='test', ip='127.0.0.1', **self.vo)

        del_account_identity('ddmlab', IdentityType.SAML, root)


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
def test_ssh_success(vo, rest_client):
    """AUTHENTICATION (REST): SSH RSA public key exchange (correct credentials)."""

    root = InternalAccount('root', vo=vo)
    try:
        add_account_identity(PUBLIC_KEY, IdentityType.SSH, root, email='ph-adp-ddm-lab@cern.ch')
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

    del_account_identity(PUBLIC_KEY, IdentityType.SSH, root)


@pytest.mark.noparallel(reason='changes identities of the same account')
def test_ssh_fail(vo, rest_client):
    """AUTHENTICATION (REST): SSH RSA public key exchange (wrong credentials)."""

    root = InternalAccount('root', vo=vo)
    try:
        add_account_identity(PUBLIC_KEY, IdentityType.SSH, root, email='ph-adp-ddm-lab@cern.ch')
    except Duplicate:
        pass  # might already exist, can skip

    signature = ssh_sign(PRIVATE_KEY, 'sign_something_else')

    headers_dict = {'X-Rucio-Account': 'root', 'X-Rucio-SSH-Signature': signature}
    response = rest_client.get('/auth/ssh', headers=headers(hdrdict(headers_dict), vohdr(vo)))
    assert response.status_code == 401

    del_account_identity(PUBLIC_KEY, IdentityType.SSH, root)


@pytest.mark.xfail(reason='The WebUI isn\'t linked to CERN SSO yet so this needs to be fixed once it is linked')
def test_saml_success(vo, rest_client):
    """AUTHENTICATION (REST): SAML Username and password (correct credentials)."""
    headers_dict = {'X-Rucio-Account': 'root'}
    userpass = {'username': 'ddmlab', 'password': 'secret'}

    response = rest_client.get('/auth/saml', headers=headers(hdrdict(headers_dict), vohdr(vo)))
    if not response.headers.get('X-Rucio-Auth-Token'):
        SAML_auth_url = response.headers.get('X-Rucio-SAML-Auth-URL')
        response = session().post(SAML_auth_url, data=userpass, verify=False, allow_redirects=True)
        response = rest_client.get('/auth/saml', headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200
    assert 'X-Rucio-Auth-Token' in response.headers
    assert len(response.headers.get('X-Rucio-Auth-Token')) > 32


@pytest.mark.xfail(reason='The WebUI isn\'t linked to CERN SSO yet so this needs to be fixed once it is linked')
def test_saml_fail(vo, rest_client):
    """AUTHENTICATION (REST): SAML Username and password (wrong credentials)."""
    headers_dict = {'X-Rucio-Account': 'root'}
    userpass = {'username': 'ddmlab', 'password': 'not_secret'}

    response = rest_client.get('/auth/saml', headers=headers(hdrdict(headers_dict), vohdr(vo)))
    if not response.headers.get('X-Rucio-Auth-Token'):
        SAML_auth_url = response.headers.get('X-Rucio-SAML-Auth-URL')
        response = session().post(SAML_auth_url, data=userpass, verify=False, allow_redirects=True)
        response = rest_client.get('/auth/saml', headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 401
