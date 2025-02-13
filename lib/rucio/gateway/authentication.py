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

from typing import TYPE_CHECKING, Any, Optional, Union

from rucio.common import exception
from rucio.common.types import InternalAccount, TokenDict
from rucio.common.utils import gateway_update_return_dict
from rucio.core import authentication, identity, oidc
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import transactional_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def refresh_cli_auth_token(
    token_string: str,
    account: str,
    issuer_nickname: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[tuple[str, int]]:
    """
    Checks if there is active refresh token and if so returns
    either active token with expiration timestamp or requests a new
    refresh and returns new access token.
    :param token_string: token string
    :param account: Rucio account for which token refresh should be considered
    :param session: The database session in use.

    :return: tuple of (access token, expiration epoch), None otherswise
    """
    internal_account = InternalAccount(account, vo=vo)
    return oidc.refresh_cli_auth_token(token_string, internal_account, issuer_nickname=issuer_nickname, vo=vo, session=session)


@transactional_session
def redirect_auth_oidc(
    authn_code: str,
    fetchtoken: bool = False,
    *,
    session: "Session"
) -> Optional[str]:
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
    return authentication.redirect_auth_oidc(authn_code, fetchtoken, session=session)


@transactional_session
def get_auth_oidc(
    account: str,
    vo: str = 'def',
    *,
    session: "Session",
    **kwargs
) -> str:
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

    internal_account = InternalAccount(account, vo=vo)
    return oidc.get_auth_oidc(internal_account, vo=vo, session=session, **kwargs)


@transactional_session
def get_token_oidc(
    auth_query_string: str,
    ip: Optional[str] = None,
    *,
    session: "Session"
) -> Optional[dict[str, Optional[Union[str, bool]]]]:
    """
    After Rucio User got redirected to Rucio /auth/oidc_code
    REST endpoints with authz code and session state encoded within the URL.
    These parameters are used to eventually gets user's info and tokens from IdP.

    :param auth_query_string: IdP redirection URL query string (AuthZ code & user session state).
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: One of the following tuples: ("token", <token>);
              ("polling", True); The result depends on the authentication strategy being used
              (polling).
    """
    # no permission layer for the moment !
    return oidc.get_token_oidc(auth_query_string, ip, session=session)


@transactional_session
def get_auth_token_user_pass(
    account: str,
    username: str,
    password: str,
    appid: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[TokenDict]:
    """
    Authenticate a Rucio account temporarily via username and password.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'username': username, 'password': password}
    auth_result = permission.has_permission(issuer=account, vo=vo, action='get_auth_token_user_pass', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('User with identity %s can not log to account %s. %s' % (username, account, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_user_pass(internal_account, username, password, appid, ip, session=session)


@transactional_session
def get_auth_token_gss(
    account: str,
    gsscred: str,
    appid: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[TokenDict]:
    """
    Authenticate a Rucio account temporarily via a GSS token.

    The tokens lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param gsscred: GSS principal@REALM as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'gsscred': gsscred}
    auth_result = permission.has_permission(issuer=account, vo=vo, action='get_auth_token_gss', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('User with identity %s can not log to account %s. %s' % (gsscred, account, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_gss(internal_account, gsscred, appid, ip, session=session)


@transactional_session
def get_auth_token_x509(
    account: Optional[str],
    dn: str,
    appid: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[TokenDict]:
    """
    Authenticate a Rucio account temporarily via an x509 certificate.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string. If account is none, the default will be used.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    if account is None:
        account = identity.get_default_account(dn, IdentityType.X509).external

    kwargs = {'account': account, 'dn': dn}
    auth_result = permission.has_permission(issuer=account, vo=vo, action='get_auth_token_x509', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('User with identity %s can not log to account %s. %s' % (dn, account, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_x509(internal_account, dn, appid, ip, session=session)


@transactional_session
def get_auth_token_ssh(
    account: str,
    signature: str,
    appid: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[TokenDict]:
    """
    Authenticate a Rucio account temporarily via SSH key exchange.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param signature: Response to challenge token signed with SSH private key as a base64 encoded string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'signature': signature}
    auth_result = permission.has_permission(issuer=account, vo=vo, action='get_auth_token_ssh', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('User with provided signature can not log to account %s. %s' % (account, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_ssh(internal_account, signature, appid, ip, session=session)


@transactional_session
def get_ssh_challenge_token(
    account: str,
    appid: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[TokenDict]:
    """
    Get a challenge token for subsequent SSH public key authentication.

    The challenge token lifetime is 5 seconds.

    :param account: Account identifier as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account}
    auth_result = permission.has_permission(issuer=account, vo=vo, action='get_auth_token_ssh', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('User can not get challenge token for account %s. %s' % (account, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return authentication.get_ssh_challenge_token(internal_account, appid, ip, session=session)


@transactional_session
def get_auth_token_saml(
    account: str,
    saml_nameid: str,
    appid: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[TokenDict]:
    """
    Authenticate a Rucio account temporarily via SSO.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param saml_nameid: NameId returned in SAML response as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    kwargs = {'account': account, 'saml_nameid': saml_nameid}
    auth_result = permission.has_permission(issuer=account, vo=vo, action='get_auth_token_saml', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('User with identity %s can not log to account %s. %s' % (saml_nameid, account, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return authentication.get_auth_token_saml(internal_account, saml_nameid, appid, ip, session=session)


@transactional_session
def validate_auth_token(
    token: str,
    *,
    session: "Session"
) -> dict[str, Any]:
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.
    :param session: The database session in use.

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope>,
                           vo: <vo> }
    """

    auth = authentication.validate_auth_token(token, session=session)
    vo = auth['account'].vo
    auth = gateway_update_return_dict(auth, session=session)
    auth['vo'] = vo
    return auth
