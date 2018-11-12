'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2012, 2017
 - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011-2017
'''

import base64

from nose.tools import assert_equal, assert_is_none, assert_is_not_none, assert_greater, assert_in
from paste.fixture import TestApp

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_ssh, get_ssh_challenge_token
from rucio.common.exception import Duplicate
from rucio.common.utils import ssh_sign
from rucio.core.identity import add_account_identity, del_account_identity
from rucio.db.sqla.constants import IdentityType
from rucio.web.rest.authentication import APP


PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq5LySllrQFpPL"\
             "614sulXQ7wnIr1aGhGtl8b+HCB/0FhMSMTHwSjX78UbfqEorZ"\
             "V16rXrWPgUpvcbp2hqctw6eCbxwqcgu3uGWaeS5A0iWRw7oXU"\
             "h6ydnVy89zGzX1FJFFDZ+AgiZ3ytp55tg1bjqqhK1OSC0pJxd"\
             "Ne878TRVVo5MLI0S/rZY2UovCSGFaQG2iLj14wz/YqI7NFMUu"\
             "JFR4e6xmNsOP7fCZ4bGMsmnhR0GmY0dWYTupNiP5WdYXAfKEx"\
             "lnvFLTlDI5Mgh4Z11NraQ8pv4YE1woolYpqOc/IMMBBXFniTT"\
             "4tC7cgikxWb9ZmFe+r4t6yCDpX4IL8L5GOQ== test_comment"

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


class TestAuthCoreApi(object):
    '''
    TestAuthCoreApi
    '''
    def test_get_auth_token_user_pass_success(self):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='secret', appid='test', ip='127.0.0.1')
        assert_is_not_none(result)

    def test_get_auth_token_user_pass_fail(self):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='not_secret', appid='test', ip='127.0.0.1')
        assert_is_none(result)

    def test_get_auth_token_ssh_success(self):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (good signature)."""

        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root', email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        challenge_token = get_ssh_challenge_token(account='root', appid='test', ip='127.0.0.1').token

        signature = base64.b64decode(ssh_sign(PRIVATE_KEY, challenge_token))

        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1')

        assert_is_not_none(result)

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root')

    def test_get_auth_token_ssh_fail(self):
        """AUTHENTICATION (CORE): SSH RSA public key exchange (wrong signature)."""

        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root', email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        signature = ssh_sign(PRIVATE_KEY, 'sign_something_else')

        result = get_auth_token_ssh(account='root', signature=signature, appid='test', ip='127.0.0.1')

        assert_is_none(result)

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root')


class TestAuthRestApi(object):
    '''
    TestAuthRestApi
    '''
    def test_userpass_fail(self):
        """AUTHENTICATION (REST): Username and password (wrong credentials)."""
        options = []
        headers = {'X-Rucio-Account': 'wrong', 'X-Rucio-Username': 'wrong', 'X-Rucio-Password': 'wrong'}
        result = TestApp(APP.wsgifunc(*options)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(result.status, 401)

    def test_userpass_success(self):
        """AUTHENTICATION (REST): Username and password (correct credentials)."""
        options = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        result = TestApp(APP.wsgifunc(*options)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(result.status, 200)
        assert_greater(len(result.header('X-Rucio-Auth-Token')), 32)

    def test_ssh_success(self):
        """AUTHENTICATION (REST): SSH RSA public key exchange (correct credentials)."""

        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root', email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        options = []
        headers = {'X-Rucio-Account': 'root'}
        result = TestApp(APP.wsgifunc(*options)).get('/ssh_challenge_token', headers=headers, expect_errors=True)
        assert_equal(result.status, 200)
        assert_in('challenge-', result.header('X-Rucio-SSH-Challenge-Token'))

        signature = ssh_sign(PRIVATE_KEY, result.header('X-Rucio-SSH-Challenge-Token'))

        headers = {'X-Rucio-Account': 'root', 'X-Rucio-SSH-Signature': signature}
        result = TestApp(APP.wsgifunc(*options)).get('/ssh', headers=headers, expect_errors=True)
        assert_equal(result.status, 200)
        assert_greater(len(result.header('X-Rucio-Auth-Token')), 32)

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root')

    def test_ssh_fail(self):
        """AUTHENTICATION (REST): SSH RSA public key exchange (wrong credentials)."""

        try:
            add_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root', email='ph-adp-ddm-lab@cern.ch')
        except Duplicate:
            pass  # might already exist, can skip

        signature = ssh_sign(PRIVATE_KEY, 'sign_something_else')

        options = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-SSH-Signature': signature}
        result = TestApp(APP.wsgifunc(*options)).get('/ssh', headers=headers, expect_errors=True)
        assert_equal(result.status, 401)

        del_account_identity(PUBLIC_KEY, IdentityType.SSH, 'root')
