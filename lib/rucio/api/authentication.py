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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from rucio.api import permission
from rucio.common import exception
from rucio.common.types import InternalAccount
from rucio.common.utils import api_update_return_dict
from rucio.core import authentication, identity, oidc
from rucio.db.sqla.constants import IdentityType


def refresh_cli_auth_token(token_string, account, vo='def'):
    """
    Checks if there is active refresh token and if so returns
    either active token with expiration timestamp or requests a new
    refresh and returns new access token.
    :param token_string: token string
    :param account: Rucio account for which token refresh should be considered

    :return: tuple of (access token, expiration epoch), None otherswise
    """
    account = InternalAccount(account, vo=vo)
    return oidc.refresh_cli_auth_token(token_string, account)


def redirect_auth_oidc(authn_code, fetchtoken=False):
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
    return authentication.redirect_auth_oidc(authn_code, fetchtoken)


def get_auth_oidc(account, vo='def', **kwargs):
    """
    Assembles the authorization request of the Rucio Client tailored to the Rucio user
    & Identity Provider. Saves authentication session parameters in the oauth_requests
    DB table (for later use-cases). This information is saved for the token lifetime
    of a token to allow token exchange and refresh.
    Returns authorization URL as a string or a redirection url to
    be used in user's browser for authentication.

    :param account: Rucio Account identifier as a string.
    :param vo: The VO to act on.
    :param auth_scope: space separated list of scope names. Scope parameter
                       defines which user's info the user allows to provide
                       to the Rucio Client.
    :param audience: audience for which tokens are requested ('rucio' is the default)
    :param auto: If True, the function will return authorization URL to the Rucio Client
                 which will log-in with user's IdP credentials automatically.
                 Also it will instruct the IdP to return an AuthZ code to another Rucio REST
                 endpoint /oidc_token. If False, the function will return a URL
                 to be used by the user in the browser in order to authenticate via IdP
                 (which will then return with AuthZ code to /oidc_code REST endpoint).
    :param polling: If True, '_polling' string will be appended to the access_msg
                    in the DB oauth_requests table to inform the authorization stage
                    that the Rucio Client is polling the server for a token
                    (and no fetchcode needs to be returned at the end).
    :param refresh_lifetime: specifies how long the OAuth daemon should
                             be refreshing this token. Default is 96 hours.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: User & Rucio OIDC Client specific Authorization or Redirection URL as a string
              OR a redirection url to be used in user's browser for authentication.
    """
    # no permission layer for the moment !

    account = InternalAccount(account, vo=vo)
    return oidc.get_auth_oidc(account, **kwargs)


def get_token_oidc(auth_query_string, ip=None):
    """
    After Rucio User got redirected to Rucio /auth/oidc_token (or /auth/oidc_code)
    REST endpoints with authz code and session state encoded within the URL.
    These parameters are used to eventually gets user's info and tokens from IdP.

    :param auth_query_string: IdP redirection URL query string (AuthZ code & user session state).
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: One of the following tuples: ("fetchcode", <code>); ("token", <token>);
              ("polling", True); The result depends on the authentication strategy being used
              (no auto, auto, polling).
    """
    # no permission layer for the moment !
    return oidc.get_token_oidc(auth_query_string, ip)


def get_auth_token_user_pass(account, username, password, appid, ip=None, vo='def'):
    """
    Authenticate a Rucio account temporarily via username and password.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'username': username, 'password': password}
    if not permission.has_permission(issuer=account, vo=vo, action='get_auth_token_user_pass', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (username, account))

    account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_user_pass(account, username, password, appid, ip)


def get_auth_token_gss(account, gsscred, appid, ip=None, vo='def'):
    """
    Authenticate a Rucio account temporarily via a GSS token.

    The tokens lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param gsscred: GSS principal@REALM as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'gsscred': gsscred}
    if not permission.has_permission(issuer=account, vo=vo, action='get_auth_token_gss', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (gsscred, account))

    account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_gss(account, gsscred, appid, ip)


def get_auth_token_x509(account, dn, appid, ip=None, vo='def'):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string. If account is none, the default will be used.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.

    :returns: A dict with token and expires_at entries.
    """

    if account is None:
        account = identity.get_default_account(dn, IdentityType.X509).external

    kwargs = {'account': account, 'dn': dn}
    if not permission.has_permission(issuer=account, vo=vo, action='get_auth_token_x509', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (dn, account))

    account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_x509(account, dn, appid, ip)


def get_auth_token_ssh(account, signature, appid, ip=None, vo='def'):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param signature: Response to challenge token signed with SSH private key as a base64 encoded string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'signature': signature}
    if not permission.has_permission(issuer=account, vo=vo, action='get_auth_token_ssh', kwargs=kwargs):
        raise exception.AccessDenied('User with provided signature can not log to account %s' % account)

    account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_ssh(account, signature, appid, ip)


def get_ssh_challenge_token(account, appid, ip=None, vo='def'):
    """
    Get a challenge token for subsequent SSH public key authentication.

    The challenge token lifetime is 5 seconds.

    :param account: Account identifier as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account}
    if not permission.has_permission(issuer=account, vo=vo, action='get_ssh_challenge_token', kwargs=kwargs):
        raise exception.AccessDenied('User can not get challenge token for account %s' % account)

    account = InternalAccount(account, vo=vo)

    return authentication.get_ssh_challenge_token(account, appid, ip)


def get_auth_token_saml(account, saml_nameid, appid, ip=None, vo='def'):
    """
    Authenticate a Rucio account temporarily via SSO.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param saml_nameid: NameId returned in SAML response as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'saml_nameid': saml_nameid}
    if not permission.has_permission(issuer=account, vo=vo, action='get_auth_token_saml', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (saml_nameid, account))

    account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_saml(account, saml_nameid, appid, ip)


def validate_auth_token(token):
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope>,
                           vo: <vo> }
              if successful, None otherwise.
    """

    auth = authentication.validate_auth_token(token)
    if auth is not None:
        vo = auth['account'].vo
        auth = api_update_return_dict(auth)
        auth['vo'] = vo
    return auth
