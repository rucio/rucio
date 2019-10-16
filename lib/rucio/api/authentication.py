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
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from rucio.api import permission
from rucio.common import exception
from rucio.common.types import InternalAccount
from rucio.common.utils import api_update_return_dict
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

    account = InternalAccount(account)

    return authentication.get_auth_token_user_pass(account, username, password, appid, ip)


def redirect_auth_OIDC(authn_code, fetchtoken=False):
    """
    Finds the Authentication URL in the Rucio DB oauth_requests table
    and redirects user's browser to this URL.

    :param auth_code: Rucio assigned code to redirect
                      authorization securely to IdP via Rucio Auth server through a browser.
    :param fetchtoken: If True, valid token temporarily saved in the oauth_requests table
                       will be returned. If False, redirection URL is returned.
    :param session: The database session in use.

    :returns: result of the query (authorization URL or a
              token if a user asks with the correct code) or None.
              Exception thrown in case of an unexpected crash.
    """
    return authentication.redirect_auth_OIDC(authn_code, fetchtoken)


def get_auth_OIDC(account, **kwargs):
    """
    Assembles the authentication request of the Rucio Client tailored to the Rucio user
    & Identity Provider. Saves temporarily authentication session parameters in the oauth_requests DB table
    (for later use when IdP returns to the Rucio Auth server with a AutzZ code).
    Returns authorization URL as a string or a redirection url to be used in user's browser to authenticate him/herself.

    :param account: Rucio Account identifier as a string.
    :param auth_scope: space separated list of scope names. Scope parameter defines which user's
                       info the user allows to provide to the Rucio Client via his/her Identity Provider
    :param audience: audience for which tokens are requested ('Rucio' is the default)
    :param auto: If True, the function will return authentication URL to the Rucio Client
           which will log-in user with his IdP credentials automatically. Also it will instruct the IdP
           to return an AuthZ code to another Rucio REST endpoint (OIDC_token).
           If False, the function will return a URL to be used by the user
           in his/her browser in order to authenticate via IdP (which will then return with AuthZ code to OIDC_code REST endpoint).
    :param polling: If True, '_polling' string will be appended to the redirect_code in the DB oauth_requests table
                    to inform the authorization stage that the Rucio Client is polling the server for a token
                    (and no fetchcode needs to be returned at the end).
    :param refresh_lifetime: specifies how long the OAuth daemon should be refreshing this token. Default is 96 hours.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: User & Rucio OIDC Client specific Authorization or Redirection URL as a string.
    """
    # no permission layer for the moment !

    account = InternalAccount(account)
    return authentication.get_auth_OIDC(account, **kwargs)


def get_token_OIDC(auth_query_string, ip=None):
    """
    After Rucio User authenticated with the Identity Provider via the authorization URL,
    and by that, granted to the Rucio OIDC client an access to her/him information (auth_scope(s)),
    the Identity Provider redirects her/him to /auth/OIDC_token (or /auth/OIDC_code) with authz code
    and session state encoded within the URL. This URL's query string becomes the input parameter
    for this function that eventually gets user's info and tokens from the Identity Provider.

    :param auth_query_string: Identity Provider redirection URL query string
                              containing AuthZ code and user session state parameters.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: One of the following tuples:
              ("fetchcode", <code>)
              ("token", <token>)
              ("polling", True)
              The result depends on the way authentication was obtained
              (via browser or if Rucio was entrusted with users IdP credentials)
    """
    # no permission layer for the moment !
    return authentication.get_token_OIDC(auth_query_string, ip)


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

    account = InternalAccount(account)

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
        account = identity.get_default_account(dn, IdentityType.X509).external

    kwargs = {'account': account, 'dn': dn}
    if not permission.has_permission(issuer=account, action='get_auth_token_x509', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (dn, account))

    account = InternalAccount(account)

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

    account = InternalAccount(account)

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

    account = InternalAccount(account)

    return authentication.get_ssh_challenge_token(account, appid, ip)


def validate_auth_token(token):
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope> }
              if successful, None otherwise.
    """

    return api_update_return_dict(authentication.validate_auth_token(token))
