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

import hashlib
import json
import logging
import subprocess
import traceback
from datetime import datetime, timedelta
from math import floor
from secrets import choice
from typing import TYPE_CHECKING, Any, Final, Optional, Union
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from dogpile.cache.api import NoValue
from jwkest.jws import JWS
from jwkest.jwt import JWT
from oic import rndstr
from oic.oic import REQUEST2ENDPOINT, Client, Grant, Token
from oic.oic.message import AccessTokenResponse, AuthorizationResponse, RegistrationResponse
from oic.utils import time_util
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from sqlalchemy import delete, null, or_, select, update
from sqlalchemy.sql.expression import true

from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.exception import CannotAuthenticate, CannotAuthorize, RucioException
from rucio.common.stopwatch import Stopwatch
from rucio.common.utils import all_oidc_req_claims_present, build_url, chunks, val_to_space_sep_str
from rucio.core.account import account_exists
from rucio.core.identity import exist_identity_account, get_default_account
from rucio.core.monitor import MetricManager
from rucio.db.sqla import filter_thread_work, models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount

# The WLCG Common JWT Profile dictates that the lifetime of access and ID tokens
# should range from five minutes to six hours.
TOKEN_MIN_LIFETIME: Final = config_get_int('oidc', 'token_min_lifetime', default=300)
TOKEN_MAX_LIFETIME: Final = config_get_int('oidc', 'token_max_lifetime', default=21600)

REGION: Final = MemcacheRegion(expiration_time=TOKEN_MAX_LIFETIME)
METRICS = MetricManager(module=__name__)

# worokaround for a bug in pyoidc (as of Dec 2019)
REQUEST2ENDPOINT['CCAccessTokenRequest'] = 'token_endpoint'

# private/protected file containing Rucio Client secrets known to the Identity Provider as well
IDPSECRETS = config_get('oidc', 'idpsecrets', False)
ADMIN_ISSUER_ID = config_get('oidc', 'admin_issuer', False)
EXPECTED_OIDC_AUDIENCE = config_get('oidc', 'expected_audience', False, 'rucio')
EXPECTED_OIDC_SCOPE = config_get('oidc', 'expected_scope', False, 'openid profile')
EXCHANGE_GRANT_TYPE = config_get('oidc', 'exchange_grant_type', False, 'urn:ietf:params:oauth:grant-type:token-exchange')
REFRESH_LIFETIME_H = config_get_int('oidc', 'default_jwt_refresh_lifetime', False, 96)

# Allow 2 mins of leeway in case Rucio and IdP server clocks are not perfectly synchronized
# this affects the token issued time (a token could be issued in the future if IdP clock is ahead)
LEEWAY_SECS = 120


# TO-DO permission layer: if scope == 'wlcg.groups'
# --> check 'profile' info (requested profile scope)


@METRICS.time_it
def _token_cache_get(
    key: str,
    min_lifetime: int = TOKEN_MIN_LIFETIME,
) -> Optional[str]:
    """Retrieve a token from the cache.

    Return ``None`` if the cache backend did not return a value, the value is
    not a valid JWT, or the token has a remaining lifetime less than
    ``min_lifetime`` seconds.
    """
    value = REGION.get(key)
    if isinstance(value, NoValue):
        METRICS.counter('token_cache.miss').inc()
        return None

    if isinstance(value, str):
        try:
            payload = JWT().unpack(value).payload()
        except Exception:
            METRICS.counter('token_cache.invalid').inc()
            return None
    else:
        METRICS.counter('token_cache.invalid').inc()
        return None

    now = datetime.utcnow().timestamp()
    expiration = payload.get('exp', 0)    # type: ignore
    if now + min_lifetime > expiration:
        METRICS.counter('token_cache.expired').inc()
        return None

    METRICS.counter('token_cache.hit').inc()
    return value


def _token_cache_set(key: str, value: str) -> None:
    """Store a token in the cache."""
    REGION.set(key, value)


def request_token(audience: str, scope: str, use_cache: bool = True) -> Optional[str]:
    """Request a token from the provider.

    Return ``None`` if the configuration was not loaded properly or the request
    was unsuccessful.
    """
    if not all([OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_PROVIDER_ENDPOINT]):
        if OIDC_CONFIGURATION_RUN or not __load_oidc_configuration():
            return None

    key = hashlib.md5(f'audience={audience};scope={scope}'.encode()).hexdigest()

    if use_cache and (token := _token_cache_get(key)):
        return token

    try:
        response = requests.post(url=OIDC_PROVIDER_ENDPOINT,
                                 auth=(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET),
                                 data={'grant_type': 'client_credentials',
                                       'audience': audience,
                                       'scope': scope})
        response.raise_for_status()
        payload = response.json()
        token = payload['access_token']
    except Exception:
        logging.debug('Failed to procure a token', exc_info=True)
        return None

    if use_cache:
        _token_cache_set(key, token)

    return token


def __get_rucio_oidc_clients(keytimeout: int = 43200) -> tuple[dict, dict]:
    """
    Creates a Rucio OIDC Client instances per Identity Provider (IdP)
    according to etc/idpsecrets.json configuration file.
    Clients have to be pre-registered with the respective IdP with the appropriate settings:
    allowed to request refresh tokens which have lifetime set in their unverified header,
    allowed to request token exchange, immediate refresh tokens expiration after first use)

    :returns: Dictionary of {'https://issuer_1/': <Rucio OIDC Client_1 instance>,
                             'https://issuer_2/': <Rucio OIDC Client_2 instance>,}.
              In case of trouble, Exception is raised.
    """
    clients = {}
    admin_clients = {}
    try:
        with open(IDPSECRETS) as client_secret_file:
            client_secrets = json.load(client_secret_file)
    except Exception:
        return (clients, admin_clients)
    for iss in client_secrets:
        try:
            client_secret = client_secrets[iss]
            issuer = client_secret["issuer"]
            client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
            # general parameter discovery about the Identity Provider via issuers URL
            client.provider_config(issuer)
            # storing client specific parameters into the client itself
            client_reg = RegistrationResponse(**client_secret)
            client.store_registration_info(client_reg)
            # setting public_key cache timeout to 'keytimeout' seconds
            keybundles = client.keyjar.issuer_keys[client.issuer]
            for keybundle in keybundles:
                keybundle.cache_time = keytimeout
            clients[issuer] = client
            # doing the same to store a Rucio Admin client
            # which has client credential flow allowed
            client_secret = client_secrets[iss]["SCIM"]
            client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
            client.provider_config(issuer)
            client_reg = RegistrationResponse(**client_secret)
            client.store_registration_info(client_reg)
            admin_clients[issuer] = client
        except Exception as error:
            raise RucioException(error.args) from error
    return (clients, admin_clients)


# global variables to represent the IdP clients
OIDC_CLIENTS = {}
OIDC_ADMIN_CLIENTS = {}
# New-style token support.
OIDC_CLIENT_ID = ''
OIDC_CLIENT_SECRET = ''
OIDC_PROVIDER_ENDPOINT = ''
OIDC_CONFIGURATION_RUN = False


def __initialize_oidc_clients() -> None:
    """
    Initialising Rucio OIDC Clients
    """

    try:
        all_oidc_clients = __get_rucio_oidc_clients()
        global OIDC_CLIENTS
        global OIDC_ADMIN_CLIENTS
        OIDC_CLIENTS = all_oidc_clients[0]
        OIDC_ADMIN_CLIENTS = all_oidc_clients[1]
    except Exception as error:
        logging.debug("OIDC clients not properly loaded: %s", error)
        pass


def __load_oidc_configuration() -> bool:
    """Load the configuration for the new-style token support."""
    global OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_PROVIDER_ENDPOINT, OIDC_CONFIGURATION_RUN

    OIDC_CONFIGURATION_RUN = True

    if not IDPSECRETS:
        logging.error('Configuration option "idpsecrets" in section "oidc" is not set')
        return False
    if not ADMIN_ISSUER_ID:
        logging.error('Configuration option "admin_issuer" in section "oidc" is not set')
        return False

    try:
        with open(IDPSECRETS) as f:
            data = json.load(f)
            OIDC_CLIENT_ID = data[ADMIN_ISSUER_ID]['client_id']
            OIDC_CLIENT_SECRET = data[ADMIN_ISSUER_ID]['client_secret']
            issuer = data[ADMIN_ISSUER_ID]['issuer']
    except Exception:
        logging.error('Failed to parse configuration file "%s"', IDPSECRETS,
                      exc_info=True)
        return False
    try:
        oidc_discover_url = urljoin(issuer, '.well-known/openid-configuration')
        response = requests.get(oidc_discover_url)
        response.raise_for_status()
        payload = response.json()
        OIDC_PROVIDER_ENDPOINT = payload['token_endpoint']
    except (requests.HTTPError, requests.JSONDecodeError, KeyError):
        logging.error('Failed to discover token endpoint', exc_info=True)
        return False

    return True


def __get_init_oidc_client(token_object: models.Token = None, token_type: str = None, **kwargs) -> dict[Any, Any]:
    """
    Get an OIDC client object, (re-)initialised with parameters corresponding
    to authorization flows used to get a token. For special cases - token refresh,
    token exchange - these parameters are being mocked as pyoidc library
    has to develop these areas. Initialisation can be made either by kwargs
    (for a authorization code flow e.g.) or via kwargs (for token exchange or token refresh).

    :param session_state: state value of the first authorization request
    :param token_object: DB token token to be included in a Grant for
                         the token exchange or token refresh mechanisms
    :param token_type: e.g. "subject_token" for token exchange or "refresh_token"
    :param kwargs: optional strings which contain expected oauth session parameters:
                   issuer_id/issuer, redirect_uri, redirect_to, state, nonce, code,
                   scope, audience,

    :returns: if first_init == True: dict {'client': oidc client object, 'request': auth_url}
              for all other cases return oidc client object. If anything goes wrong, exception is thrown.
    """

    if not OIDC_CLIENTS:
        # retry once loading OIDC clients
        __initialize_oidc_clients()
        if not OIDC_CLIENTS:
            raise CannotAuthenticate(traceback.format_exc())

    try:

        auth_args = {"grant_types": ["authorization_code"],
                     "response_type": "code",
                     "state": kwargs.get('state', rndstr()),
                     "nonce": kwargs.get('nonce', rndstr())}
        auth_args["scope"] = token_object.oidc_scope if token_object else kwargs.get('scope', " ")
        if config_get_bool('oidc', 'supports_audience', raise_exception=False, default=True):
            auth_args["audience"] = token_object.audience if token_object else kwargs.get('audience', " ")

        if token_object:
            issuer = token_object.identity.split(", ")[1].split("=")[1]
            oidc_client = OIDC_CLIENTS[issuer]
            auth_args["client_id"] = oidc_client.client_id
            token = ''
            if not token_type:
                token_type = kwargs.get('token_type', None)
            if token_type == 'subject_token':  # noqa: S105
                token = token_object.token
                # do not remove - even though None, oic expects this key to exist
                auth_args["redirect_uri"] = None
            if token_type == 'refresh_token':  # noqa: S105
                token = token_object.refresh_token
                # do not remove - even though None, oic expects this key to exist
                auth_args["redirect_uri"] = None
            if token_type and token:
                oidc_client.grant[auth_args['state']] = Grant()
                oidc_client.grant[auth_args['state']].grant_expiration_time = time_util.utc_time_sans_frac() + 300
                resp = AccessTokenResponse()
                resp[token_type] = token
                oidc_client.grant[auth_args['state']].tokens.append(Token(resp))
        else:
            secrets, client_secret = {}, {}
            try:
                with open(IDPSECRETS) as client_secret_file:
                    secrets = json.load(client_secret_file)
            except Exception as error:
                raise CannotAuthenticate("Rucio server is missing information from the idpsecrets.json file.") from error
            if 'issuer_id' in kwargs:
                client_secret = secrets[kwargs.get('issuer_id', ADMIN_ISSUER_ID)]
            elif 'issuer' in kwargs:
                client_secret = next((secrets[i] for i in secrets if 'issuer' in secrets[i] and  # NOQA: W504
                                      kwargs.get('issuer') in secrets[i]['issuer']), None)
            redirect_url = kwargs.get('redirect_uri', None)
            if not redirect_url:
                redirect_to = kwargs.get("redirect_to", "auth/oidc_token")
                redirect_urls = [u for u in client_secret["redirect_uris"] if redirect_to in u]
                redirect_url = choice(redirect_urls)
            if not redirect_url:
                raise CannotAuthenticate("Could not pick any redirect URL(s) from the ones defined "
                                         + "in Rucio OIDC Client configuration file.")  # NOQA: W503
            auth_args["redirect_uri"] = redirect_url
            oidc_client = OIDC_CLIENTS[client_secret["issuer"]]
            auth_args["client_id"] = oidc_client.client_id

        if kwargs.get('first_init', False):
            auth_url = build_url(oidc_client.authorization_endpoint, params=auth_args)
            return {'redirect': redirect_url, 'auth_url': auth_url}

        oidc_client.construct_AuthorizationRequest(request_args=auth_args)
        # parsing the authorization query string by the Rucio OIDC Client (creates a Grant)
        oidc_client.parse_response(AuthorizationResponse,
                                   info='code=' + kwargs.get('code', rndstr()) + '&state=' + auth_args['state'],
                                   sformat="urlencoded")
        return {'client': oidc_client, 'state': auth_args['state']}
    except Exception as error:
        raise CannotAuthenticate(traceback.format_exc()) from error


@transactional_session
def get_auth_oidc(account: str, *, session: "Session", **kwargs) -> str:
    """
    Assembles the authorization request of the Rucio Client tailored to the Rucio user
    & Identity Provider. Saves authentication session parameters in the oauth_requests
    DB table (for later use-cases). This information is saved for the token lifetime
    of a token to allow token exchange and refresh.
    Returns authorization URL as a string or a redirection url to
    be used in user's browser for authentication.

    :param account: Rucio Account identifier as a string.
    :param auth_scope: space separated list of scope names. Scope parameter
                       defines which user's info the user allows to provide
                       to the Rucio Client.
    :param audience: audience for which tokens are requested (EXPECTED_OIDC_AUDIENCE is the default)
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
    # TO-DO - implement a check if that account already has a valid
    # token with the required scope and audience and return such token !
    auth_scope = kwargs.get('auth_scope', EXPECTED_OIDC_SCOPE)
    if not auth_scope:
        auth_scope = EXPECTED_OIDC_SCOPE
    audience = kwargs.get('audience', EXPECTED_OIDC_AUDIENCE)
    if not audience:
        audience = EXPECTED_OIDC_AUDIENCE
    # checking that minimal audience and scope requirements (required by Rucio) are satisfied !
    if not all_oidc_req_claims_present(auth_scope, audience, EXPECTED_OIDC_SCOPE, EXPECTED_OIDC_AUDIENCE):
        raise CannotAuthenticate("Requirements of scope and audience do not satisfy minimal requirements of the Rucio server.")
    issuer_id = kwargs.get('issuer', ADMIN_ISSUER_ID)
    if not issuer_id:
        issuer_id = ADMIN_ISSUER_ID
    polling = kwargs.get('polling', False)
    refresh_lifetime = kwargs.get('refresh_lifetime', REFRESH_LIFETIME_H)
    ip = kwargs.get('ip', None)
    # Make sure the account exists
    if not account_exists(account, session=session):
        logging.debug("Account %s does not exist.", account)
        return None

    try:
        stopwatch = Stopwatch()
        # redirect_url needs to be specified & one of those defined
        # in the Rucio OIDC Client configuration
        redirect_to = "auth/oidc_code"
        # random strings in order to keep track of responses to outstanding requests (state)
        # and to associate a client session with an ID Token and to mitigate replay attacks (nonce).
        state, nonce = rndstr(50), rndstr(50)
        # in the following statement we retrieve the authorization endpoint
        # from the client of the issuer and build url
        oidc_dict = __get_init_oidc_client(issuer_id=issuer_id, redirect_to=redirect_to,
                                           state=state, nonce=nonce,
                                           scope=auth_scope, audience=audience, first_init=True)
        auth_url = oidc_dict['auth_url']
        redirect_url = oidc_dict['redirect']
        # redirect code is put in access_msg and returned to the user
        access_msg = None
        access_msg = rndstr(23)
        if polling:
            access_msg += '_polling'
        # Making sure refresh_lifetime is an integer or None.
        if refresh_lifetime:
            refresh_lifetime = int(refresh_lifetime)
        # Specifying temporarily 5 min lifetime for the authentication session.
        expired_at = datetime.utcnow() + timedelta(seconds=300)
        # saving session parameters into the Rucio DB
        oauth_session_params = models.OAuthRequest(account=account,
                                                   state=state,
                                                   nonce=nonce,
                                                   access_msg=access_msg,
                                                   redirect_msg=auth_url,
                                                   expired_at=expired_at,
                                                   refresh_lifetime=refresh_lifetime,
                                                   ip=ip)
        oauth_session_params.save(session=session)
        _delete_oauth_request_by_account_and_expiration(account, session=session)
        # If user selected authentication via web browser, a redirection
        # URL is returned instead of the direct URL pointing to the IdP.
        # the following takes into account deployments where the base url of the rucio server is
        # not equivalent to the network location, e.g. if the server is proxied
        auth_server = urlparse(redirect_url)
        auth_url = build_url('https://' + auth_server.netloc, path='{}auth/oidc_redirect'.format(
            auth_server.path.split('auth/')[0].lstrip('/')), params=access_msg)

        METRICS.timer('IdP_authentication.request').observe(stopwatch.elapsed)
        return auth_url

    except Exception as error:
        raise CannotAuthenticate(traceback.format_exc()) from error


@transactional_session
def get_token_oidc(
    auth_query_string: str,
    ip: Optional[str] = None,
    *,
    session: "Session"
) -> Optional[dict[str, Optional[Union[str, bool]]]]:
    """
    After Rucio User got redirected to Rucio /auth/oidc_token (or /auth/oidc_code)
    REST endpoints with authz code and session state encoded within the URL.
    These parameters are used to eventually gets user's info and tokens from IdP.

    :param auth_query_string: IdP redirection URL query string (AuthZ code & user session state).
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: One of the following tuples: ("fetchcode", <code>);
              ("polling", True); The result depends on the authentication strategy being used
              (no polling, polling).
    """
    try:
        stopwatch = Stopwatch()
        parsed_authquery = parse_qs(auth_query_string)
        state = parsed_authquery["state"][0]
        code = parsed_authquery["code"][0]
        # getting oauth request params from the oauth_requests DB Table
        query = select(
            models.OAuthRequest
        ).where(
            models.OAuthRequest.state == state
        )
        oauth_req_params = session.execute(query).scalar()
        if oauth_req_params is None:
            raise CannotAuthenticate("User related Rucio OIDC session could not keep "
                                     + "track of responses from outstanding requests.")  # NOQA: W503
        req_url = urlparse(oauth_req_params.redirect_msg or '')
        issuer = req_url.scheme + "://" + req_url.netloc
        req_params = parse_qs(req_url.query)
        client_params = {}
        for key in list(req_params):
            client_params[key] = val_to_space_sep_str(req_params[key])

        oidc_client = __get_init_oidc_client(issuer=issuer, code=code, **client_params)['client']
        METRICS.counter(name='IdP_authentication.code_granted').inc()
        # exchange access code for a access token
        oidc_tokens = oidc_client.do_access_token_request(state=state,
                                                          request_args={"code": code},
                                                          authn_method="client_secret_basic",
                                                          skew=LEEWAY_SECS)
        if 'error' in oidc_tokens:
            raise CannotAuthorize(oidc_tokens['error'])
        # mitigate replay attacks
        nonce = oauth_req_params.nonce
        if oidc_tokens['id_token']['nonce'] != nonce:
            raise CannotAuthenticate("ID token could not be associated with the Rucio OIDC Client"
                                     + " session. This points to possible replay attack !")  # NOQA: W503

        account = oauth_req_params.account
        # starting to fill dictionary with parameters for token DB row
        jwt_row_dict, extra_dict = {}, {}
        jwt_row_dict['identity'] = oidc_identity_string(oidc_tokens['id_token']['sub'],
                                                        oidc_tokens['id_token']['iss'])
        jwt_row_dict['account'] = oauth_req_params.account


        # check if given account has the identity registered
        if not exist_identity_account(jwt_row_dict['identity'], IdentityType.OIDC, jwt_row_dict['account'], session=session):
            raise CannotAuthenticate("OIDC identity '%s' of the '%s' account is unknown to Rucio."
                                     % (jwt_row_dict['identity'], str(jwt_row_dict['account'])))
        METRICS.counter(name='success').inc()
        # get access token expiry timestamp
        jwt_row_dict['lifetime'] = datetime.utcnow() + timedelta(seconds=oidc_tokens['expires_in'])
        # get audience and scope info from the token
        if 'scope' in oidc_tokens and 'audience' in oidc_tokens:
            jwt_row_dict['authz_scope'] = val_to_space_sep_str(oidc_tokens['scope'])
            jwt_row_dict['audience'] = val_to_space_sep_str(oidc_tokens['audience'])
        elif 'access_token' in oidc_tokens:
            try:
                values = __get_keyvalues_from_claims(oidc_tokens['access_token'], ['scope', 'aud'])
                jwt_row_dict['authz_scope'] = values['scope']
                jwt_row_dict['audience'] = values['aud']
            except Exception:
                # we assume the Identity Provider did not do the right job here
                jwt_row_dict['authz_scope'] = None
                jwt_row_dict['audience'] = None
        # groups = oidc_tokens['id_token']['groups']
        # nothing done with group info for the moment - TO-DO !
        # collect extra token DB row parameters
        extra_dict = {}
        extra_dict['ip'] = ip
        extra_dict['state'] = state
        # In case user requested to grant Rucio a refresh token,
        # this token will get saved in the DB and an automatic refresh
        # for a specified period of time will be initiated (done by the Rucio daemon).
        if 'refresh_token' in oidc_tokens:
            extra_dict['refresh_token'] = oidc_tokens['refresh_token']
            extra_dict['refresh'] = True
            extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
            try:
                if oauth_req_params.refresh_lifetime is not None:
                    extra_dict['refresh_lifetime'] = int(oauth_req_params.refresh_lifetime)
            except Exception:
                pass
            try:
                values = __get_keyvalues_from_claims(oidc_tokens['refresh_token'], ['exp'])
                exp = values['exp']
                extra_dict['refresh_expired_at'] = datetime.utcfromtimestamp(float(exp))
            except Exception:
                # 4 day expiry period by default
                extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)

        new_token = __save_validated_token(oidc_tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
        METRICS.counter(name='IdP_authorization.access_token.saved').inc()
        __delete_expired_tokens_account(account=account, session=session)
        if 'refresh_token' in oidc_tokens:
            METRICS.counter(name='IdP_authorization.refresh_token.saved').inc()
        # In case authentication via browser was requested,
        # we save the token in the oauth_requests table
        if oauth_req_params.access_msg:
            # If Rucio Client waits for a fetchcode, we save the token under this code in the DB.
            if 'http' not in oauth_req_params.access_msg:
                if '_polling' not in oauth_req_params.access_msg:
                    fetchcode = rndstr(50)
                    query = update(
                        models.OAuthRequest
                    ).where(
                        models.OAuthRequest.state == state
                    ).values({
                        models.OAuthRequest.access_msg: fetchcode,
                        models.OAuthRequest.redirect_msg: new_token['token']
                    })
                # If Rucio Client was requested to poll the Rucio Auth server
                # for a token automatically, we save the token under a access_msg.
                else:
                    query = update(
                        models.OAuthRequest
                    ).where(
                        models.OAuthRequest.state == state
                    ).values({
                        models.OAuthRequest.access_msg: oauth_req_params.access_msg,
                        models.OAuthRequest.redirect_msg: new_token['token']
                    })
                session.execute(query)
                session.commit()
            METRICS.timer('IdP_authorization').observe(stopwatch.elapsed)
            if '_polling' in oauth_req_params.access_msg:
                return {'polling': True}
            else:
                return {'fetchcode': fetchcode}
        else:
            METRICS.timer('IdP_authorization').observe(stopwatch.elapsed)
            return {'token': new_token}

    except Exception:
        # TO-DO catch different exceptions - InvalidGrant etc. ...
        METRICS.counter(name='IdP_authorization.access_token.exception').inc()
        logging.debug(traceback.format_exc())
        return None
        # raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def __change_refresh_state(token: str, refresh: bool = False, *, session: "Session"):
    """
    Changes token refresh state to True/False.

    :param token:      the access token for which the refresh value should be changed.
    """
    try:
        query = update(
            models.Token
        ).where(
            models.Token.token == token
        )
        if refresh:
            # update refresh column for a token to True
            query = query.values({
                models.Token.refresh: True
            })
        else:
            query = query.values({
                models.Token.refresh: False,
                models.Token.refresh_expired_at: datetime.utcnow()
            })
        session.execute(query)
    except Exception as error:
        raise RucioException(error.args) from error


@transactional_session
def refresh_cli_auth_token(token_string: str, account: str, *, session: "Session") -> Optional[tuple[str, int]]:
    """
    Checks if there is active refresh token and if so returns
    either active token with expiration timestamp or requests a new
    refresh and returns new access token.
    :param token_string: token string
    :param account: Rucio account for which token refresh should be considered

    :return: tuple of (access token, expiration epoch), None otherswise
    """
    # only validated tokens are in the DB, check presence of token_string
    query = select(
        models.Token
    ).where(
        models.Token.token == token_string,
        models.Token.account == account,
        models.Token.expired_at > datetime.utcnow()
    ).with_for_update(
        skip_locked=True
    )
    account_token = session.execute(query).scalar()

    # if token does not exist in the DB, return None
    if account_token is None:
        logging.debug("No valid token exists for account %s.", account)
        return None

    # protection (!) no further action should be made
    # for token_string without refresh_token in the DB !
    if account_token.refresh_token is None:
        logging.debug("No refresh token exists for account %s.", account)
        return None

    # if the token exists, check if it was refreshed already, if not, refresh it
    if account_token.refresh:
        # protection (!) returning the same token if the token_string
        # is a result of a refresh which happened in the last 5 min
        datetime_min_ago = datetime.utcnow() - timedelta(seconds=300)
        if account_token.updated_at > datetime_min_ago:
            epoch_exp = int(floor((account_token.expired_at - datetime(1970, 1, 1)).total_seconds()))
            new_token_string = account_token.token
            return new_token_string, epoch_exp

        # asking for a refresh of this token
        new_token = __refresh_token_oidc(account_token, session=session)
        new_token_string = new_token['token']
        epoch_exp = int(floor((new_token['expires_at'] - datetime(1970, 1, 1)).total_seconds()))
        return new_token_string, epoch_exp

    else:
        # find account token with the same scope,
        # audience and has a valid refresh token
        query = select(
            models.Token
        ).where(
            models.Token.refresh == true(),
            models.Token.refresh_expired_at > datetime.utcnow(),
            models.Token.account == account,
            models.Token.expired_at > datetime.utcnow()
        ).with_for_update(
            skip_locked=True
        )
        new_token = session.execute(query).scalar()
        if new_token is None:
            return None

        # if the new_token has same audience and scopes as the original
        # account_token --> return this token and exp timestamp to the user
        if all_oidc_req_claims_present(new_token.oidc_scope, new_token.audience,
                                       account_token.oidc_scope, account_token.audience):
            epoch_exp = int(floor((new_token.expired_at - datetime(1970, 1, 1)).total_seconds()))
            new_token_string = new_token.token
            return new_token_string, epoch_exp
        # if scopes and audience are not the same, return None
        logging.debug("No token could be returned for refresh operation for account %s.", account)
        return None


@METRICS.time_it
@transactional_session
def __refresh_token_oidc(token_object: models.Token, *, session: "Session"):
    """
    Requests new access and refresh tokens from the Identity Provider.
    Assumption: The Identity Provider issues refresh tokens for one time use only and
    with a limited lifetime. The refresh tokens are invalidated no matter which of these
    situations happens first.

    :param token_object: Rucio models.Token DB row object

    :returns: A dict with token and expires_at entries if all went OK, None if
        refresh was not possible due to token invalidity or refresh lifetime
        constraints. Otherwise, throws an an Exception.
    """
    try:
        jwt_row_dict, extra_dict = {}, {}
        jwt_row_dict['account'] = token_object.account
        jwt_row_dict['identity'] = token_object.identity
        extra_dict['refresh_start'] = datetime.utcnow()
        # check if refresh token started in the past already
        if hasattr(token_object, 'refresh_start'):
            if token_object.refresh_start:
                extra_dict['refresh_start'] = token_object.refresh_start
        # check if refresh lifetime is set for the token
        extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
        if token_object.refresh_lifetime:
            extra_dict['refresh_lifetime'] = token_object.refresh_lifetime
        # if the token has been refreshed for time exceeding
        # the refresh_lifetime, the attempt will be aborted and refresh stopped
        if datetime.utcnow() - extra_dict['refresh_start'] > timedelta(hours=extra_dict['refresh_lifetime']):
            __change_refresh_state(token_object.token, refresh=False, session=session)
            return None
        oidc_dict = __get_init_oidc_client(token_object=token_object, token_type="refresh_token")  # noqa: S106
        oidc_client = oidc_dict['client']
        # getting a new refreshed set of tokens
        state = oidc_dict['state']
        oidc_tokens = oidc_client.do_access_token_refresh(state=state, skew=LEEWAY_SECS)
        if 'error' in oidc_tokens:
            raise CannotAuthorize(oidc_tokens['error'])
        METRICS.counter(name='IdP_authorization.refresh_token.refreshed').inc()
        # get audience and scope information
        if 'scope' in oidc_tokens and 'audience' in oidc_tokens:
            jwt_row_dict['authz_scope'] = val_to_space_sep_str(oidc_tokens['scope'])
            jwt_row_dict['audience'] = val_to_space_sep_str(oidc_tokens['audience'])
        elif 'access_token' in oidc_tokens:
            values = __get_keyvalues_from_claims(oidc_tokens['access_token'], ['scope', 'aud'])
            jwt_row_dict['authz_scope'] = values['scope']
            jwt_row_dict['audience'] = values['aud']
        # save new access and refresh tokens in the DB
        if 'refresh_token' in oidc_tokens and 'access_token' in oidc_tokens:
            # aborting refresh of the original token
            # (keeping it in place until it expires)
            __change_refresh_state(token_object.token, refresh=False, session=session)

            # get access token expiry timestamp
            jwt_row_dict['lifetime'] = datetime.utcnow() + timedelta(seconds=oidc_tokens['expires_in'])
            extra_dict['refresh'] = True
            extra_dict['refresh_token'] = oidc_tokens['refresh_token']
            try:
                values = __get_keyvalues_from_claims(oidc_tokens['refresh_token'], ['exp'])
                extra_dict['refresh_expired_at'] = datetime.utcfromtimestamp(float(values['exp']))
            except Exception:
                # 4 day expiry period by default
                extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)
            new_token = __save_validated_token(oidc_tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
            METRICS.counter(name='IdP_authorization.access_token.saved').inc()
            METRICS.counter(name='IdP_authorization.refresh_token.saved').inc()
        else:
            raise CannotAuthorize("OIDC identity '%s' of the '%s' account is did not " % (token_object.identity, token_object.account)
                                  + "succeed requesting a new access and refresh tokens.")  # NOQA: W503
        return new_token

    except Exception as error:
        METRICS.counter(name='IdP_authorization.refresh_token.exception').inc()
        raise CannotAuthorize(traceback.format_exc()) from error


@transactional_session
def delete_expired_oauthrequests(total_workers: int, worker_number: int, limit: int = 1000, *, session: "Session"):
    """
    Delete expired OAuth request parameters.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of oauth request session parameters to delete.
    :param session:            Database session in use.

    :returns: number of deleted rows
    """

    try:
        # get expired OAuth request parameters
        query = select(
            models.OAuthRequest.state
        ).where(
            models.OAuthRequest.expired_at < datetime.utcnow()
        ).order_by(
            models.OAuthRequest.expired_at
        )
        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='state')
        # limiting the number of oauth requests deleted at once
        query = query.limit(limit)
        # Oracle does not support chaining order_by(), limit(), and
        # with_for_update(). Use a nested query to overcome this.
        if session.bind.dialect.name == 'oracle':
            query = select(
                models.OAuthRequest.state
            ).where(
                models.OAuthRequest.state.in_(query)
            ).with_for_update(
                skip_locked=True
            )
        else:
            query = query.with_for_update(skip_locked=True)

        ndeleted = 0
        for states in session.execute(query).scalars().partitions(10):
            query = delete(
                models.OAuthRequest
            ).where(
                models.OAuthRequest.state.in_(states)
            )
            ndeleted += session.execute(query).rowcount
        return ndeleted
    except Exception as error:
        raise RucioException(error.args) from error

@transactional_session
def __delete_expired_tokens_account(
    account: "InternalAccount",
    *,
    session: "Session"
) -> None:
    """
    Delete expired tokens from the database.

    :param account: Account to delete expired tokens.
    :param session: The database session in use.
    """
    query = select(
        models.Token.token
    ).where(
        models.Token.expired_at <= datetime.utcnow(),
        models.Token.account == account,
        or_(
            models.Token.refresh_expired_at == null(),
            models.Token.refresh_expired_at <= datetime.utcnow()
        )).with_for_update(
        skip_locked=True
    )
    tokens = session.execute(query).scalars().all()

    for chunk in chunks(tokens, 100):
        delete_query = delete(
            models.Token
        ).prefix_with(
            "/*+ INDEX(TOKENS_ACCOUNT_EXPIRED_AT_IDX) */"
        ).where(
            models.Token.token.in_(chunk)
        )
        session.execute(delete_query)



def __get_keyvalues_from_claims(token: str, keys=None):
    """
    Extracting claims from token, e.g. scope and audience.
    :param token: the JWT to be unpacked
    :param key: list of key names to extract from the token claims

    :returns: The list of unicode values under the key, throws an exception otherwise.
    """
    resdict = {}
    try:
        claims = JWT().unpack(token).payload()
        if not keys:
            keys = claims.keys()
        for key in keys:
            value = ''
            if key in claims:
                value = val_to_space_sep_str(claims[key])  # type: ignore
            resdict[key] = value
        return resdict
    except Exception as error:
        raise CannotAuthenticate(traceback.format_exc()) from error


@read_session
def __get_rucio_jwt_dict(jwt: str, account=None, *, session: "Session"):
    """
    Get a Rucio token dictionary from token claims.
    Check token expiration and find default Rucio
    account for token identity.
    :param jwt: JSON Web Token to be inspected
    :param session: DB session in use

    :returns: Rucio token dictionary, None otherwise
    """
    try:
        # getting token paylod
        token_payload = __get_keyvalues_from_claims(jwt)
        identity_string = oidc_identity_string(token_payload['sub'], token_payload['iss'])
        expiry_date = datetime.utcfromtimestamp(float(token_payload['exp']))
        if expiry_date < datetime.utcnow():  # check if expired
            logging.debug("Token has already expired since: %s", str(expiry_date))
            return None
        scope = None
        audience = None
        if 'scope' in token_payload:
            scope = val_to_space_sep_str(token_payload['scope'])
        if 'aud' in token_payload:
            audience = val_to_space_sep_str(token_payload['aud'])
        if not account:
            # this assumes token has been previously looked up in DB
            # before to be sure that we do not have the right account already in the DB !
            account = get_default_account(identity_string, IdentityType.OIDC, True, session=session)
        else:
            if not exist_identity_account(identity_string, IdentityType.OIDC, account, session=session):
                logging.debug("No OIDC identity exists for account: %s", str(account))
                return None
        value = {'account': account,
                 'identity': identity_string,
                 'lifetime': expiry_date,
                 'audience': audience,
                 'authz_scope': scope}
        return value
    except Exception:
        logging.debug(traceback.format_exc())
        return None


@transactional_session
def __save_validated_token(token, valid_dict, extra_dict=None, *, session: "Session"):
    """
    Save JWT token to the Rucio DB.

    :param token: Authentication token as a variable-length string.
    :param valid_dict: Validation Rucio dictionary as the output
                       of the __get_rucio_jwt_dict function
    :raises RucioException: on any error
    :returns: A dict with token and expires_at entries.
    """
    try:
        if not extra_dict:
            extra_dict = {}
        new_token = models.Token(account=valid_dict.get('account', None),
                                 token=token,
                                 oidc_scope=valid_dict.get('authz_scope', None),
                                 expired_at=valid_dict.get('lifetime', None),
                                 audience=valid_dict.get('audience', None),
                                 identity=valid_dict.get('identity', None),
                                 refresh=extra_dict.get('refresh', False),
                                 refresh_token=extra_dict.get('refresh_token', None),
                                 refresh_expired_at=extra_dict.get('refresh_expired_at', None),
                                 refresh_lifetime=extra_dict.get('refresh_lifetime', None),
                                 refresh_start=extra_dict.get('refresh_start', None),
                                 ip=extra_dict.get('ip', None))
        new_token.save(session=session)

        return token_dictionary(new_token)

    except Exception as error:
        raise RucioException(error.args) from error


@transactional_session
def validate_jwt(json_web_token: str, *, session: "Session") -> dict[str, Any]:
    """
    Verifies signature and validity of a JSON Web Token.
    Gets the issuer public keys from the oidc_client
    and verifies the validity of the token.
    Used only for external tokens, not known to Rucio DB.

    :param json_web_token: the JWT string to verify

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope> }
              if successful.
    :raises: CannotAuthenticate if unsuccessful
    """

    if not OIDC_CLIENTS:
        # retry once loading OIDC clients
        __initialize_oidc_clients()
        if not OIDC_CLIENTS:
            raise CannotAuthenticate(traceback.format_exc())

    try:

        # getting issuer from the token payload
        token_dict: Optional[dict[str, Any]] = __get_rucio_jwt_dict(json_web_token, session=session)
        if not token_dict:
            raise CannotAuthenticate(traceback.format_exc())
        issuer = token_dict['identity'].split(", ")[1].split("=")[1]
        oidc_client = OIDC_CLIENTS[issuer]
        issuer_keys = oidc_client.keyjar.get_issuer_keys(issuer)
        JWS().verify_compact(json_web_token, issuer_keys)
        # if there is no audience and scope information,
        # try to get it from IdP introspection endpoint
        # TO-BE-REMOVED - once all IdPs support scope and audience in token claims !!!
        if not token_dict['authz_scope'] or not token_dict['audience']:
            clprocess = subprocess.Popen(['curl', '-s', '-L', '-u', '%s:%s'  # noqa: S607
                                          % (oidc_client.client_id, oidc_client.client_secret),
                                          '-d', 'token=%s' % (json_web_token),
                                          oidc_client.introspection_endpoint],
                                         shell=False, stdout=subprocess.PIPE)
            inspect_claims = json.loads(clprocess.communicate()[0])
            try:
                token_dict['audience'] = inspect_claims['aud']
                token_dict['authz_scope'] = inspect_claims['scope']
            except Exception:
                pass
        METRICS.counter(name='JSONWebToken.valid').inc()
        # if token is valid and coming from known issuer --> check aud and scope and save it if unknown
        if token_dict['authz_scope'] and token_dict['audience']:
            if all_oidc_req_claims_present(token_dict['authz_scope'], token_dict['audience'], EXPECTED_OIDC_SCOPE, EXPECTED_OIDC_AUDIENCE):
                # save the token in Rucio DB giving the permission to use it for Rucio operations
                __save_validated_token(json_web_token, token_dict, session=session)
            else:
                logging.debug("Token audience [%s] or scope [%s] verification failed.", token_dict['audience'], token_dict['authz_scope'])
                raise CannotAuthenticate(traceback.format_exc())
        else:
            logging.debug("Token audience or scope not present.")
            raise CannotAuthenticate(traceback.format_exc())
        METRICS.counter(name='JSONWebToken.saved').inc()
        return token_dict
    except Exception:
        METRICS.counter(name='JSONWebToken.invalid').inc()
        logging.debug(traceback.format_exc())
        raise CannotAuthenticate(traceback.format_exc())


def oidc_identity_string(sub: str, iss: str):
    """
    Transform IdP sub claim and issuers url into users identity string.
    :param sub: users SUB claim from the Identity Provider
    :param iss: issuer (IdP) https url

    :returns: OIDC identity string "SUB=<usersid>, ISS=https://iam-test.ch/"
    """
    return 'SUB=' + str(sub) + ', ISS=' + str(iss)


@transactional_session
def _delete_oauth_request_by_account_and_expiration(
    account: str,
    *,
    session: "Session"
) -> None:
    """
    Delete an OAuth request by its account and expiration time.

    :param account: The account associated with the OAuth request.
    :param session: Database session in use.
    """
    query = select(
        models.OAuthRequest.state
    ).where(
        models.OAuthRequest.expired_at <= datetime.utcnow(),
        models.OAuthRequest.account == account
    ).with_for_update(
        skip_locked=True
    )

    # Execute the query and fetch all matching states
    oauth_requests = session.execute(query).scalars().all()

    # Process deletion in chunks
    for chunk in chunks(oauth_requests, 100):
        delete_query = delete(
            models.OAuthRequest
        ).where(
            models.OAuthRequest.state.in_(chunk)
        )
        session.execute(delete_query)

    # Commit the transaction
    session.commit()

def token_dictionary(token: models.Token):
    return {'token': token.token, 'expires_at': token.expired_at}
