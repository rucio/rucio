# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario@lassnig.net>, 2012-2018
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2015
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
#
# PY3K COMPATIBLE

from rucio.api import permission
from rucio.common import exception
from rucio.core import authentication, identity
from rucio.db.sqla.constants import IdentityType


def get_auth_token_user_pass(account, username, password, appid, ip=None):
    """
    Authenticate a Rucio account temporarily via username and password.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :returns: Authentication token as a variable-length string.
    """

    kwargs = {'account': account, 'username': username, 'password': password}
    if not permission.has_permission(issuer=account, action='get_auth_token_user_pass', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (username, account))

    return authentication.get_auth_token_user_pass(account, username, password, appid, ip)


def get_auth_OIDC(account, server_name):
    """
    Authenticates Rucio user with the user's Identity Provider (XDC IAM) - issuer -
    and returns an authorization URL (as a string) with which the user can grant
    permissions to Rucio to extract his/her ID & tokens from the Identity Provider.
    (for more Identity Providers if necessary in the future,
    the 'issuer' should become another input parameter here)

    :param account: Rucio Account identifier as a string.

    :returns: User & Rucio OIDC Client specific Authorization URL as a string.
    """
    # no permission layer for the moment !
    return authentication.get_auth_OIDC(account, server_name)


def get_token_OIDC(auth_response_url, server_name):
    """
    After Rucio User grants access to the Rucio OIDC client to his information,
    the Identity Provider redirects her/him to /auth/OIDC_Token with authz code
    and session state encoded within the URL. This URL becomes the input parameter
    for the Rucio OIDC Client to get user's info and tokens from the Identity Provider.

    :param auth_response_url: Identity Provider redirection URL with authz code and user session state parameters encoded within.

    :returns: Access token as a variable-length string.
    """
    # no permission layer for the moment !
    return authentication.get_token_OIDC(auth_response_url, server_name)


def get_auth_token_gss(account, gsscred, appid, ip=None):
    """
    Authenticate a Rucio account temporarily via a GSS token.

    The tokens lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param gsscred: GSS principal@REALM as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :returns: Authentication token as a variable-length string.
    """

    kwargs = {'account': account, 'gsscred': gsscred}
    if not permission.has_permission(issuer=account, action='get_auth_token_gss', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (gsscred, account))

    return authentication.get_auth_token_gss(account, gsscred, appid, ip)


def get_auth_token_x509(account, dn, appid, ip=None):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string. If account is none, the default will be used.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :returns: Authentication token as a variable-length string.
    """

    if account is None:
        account = identity.get_default_account(dn, IdentityType.X509)

    kwargs = {'account': account, 'dn': dn}
    if not permission.has_permission(issuer=account, action='get_auth_token_x509', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (dn, account))

    return authentication.get_auth_token_x509(account, dn, appid, ip)


def get_auth_token_ssh(account, signature, appid, ip=None):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param signature: Response to challenge token signed with SSH private key as a base64 encoded string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :returns: Authentication token as a variable-length string.
    """

    kwargs = {'account': account, 'signature': signature}
    if not permission.has_permission(issuer=account, action='get_auth_token_ssh', kwargs=kwargs):
        raise exception.AccessDenied('User with provided signature can not log to account %s' % account)

    return authentication.get_auth_token_ssh(account, signature, appid, ip)


def get_ssh_challenge_token(account, appid, ip=None):
    """
    Get a challenge token for subsequent SSH public key authentication.

    The challenge token lifetime is 5 seconds.

    :param account: Account identifier as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :returns: Challenge token as a variable-length string.
    """

    kwargs = {'account': account}
    if not permission.has_permission(issuer=account, action='get_ssh_challenge_token', kwargs=kwargs):
        raise exception.AccessDenied('User can not get challenge token for account %s' % account)

    return authentication.get_ssh_challenge_token(account, appid, ip)


def validate_auth_token(token):
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.
    :returns: Tuple(account identifier, token lifetime) if successful, None otherwise.
    """

    return authentication.validate_auth_token(token)
