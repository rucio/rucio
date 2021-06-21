# -*- coding: utf-8 -*-
# Copyright 2019-2021 CERN
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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

import json
import random
import subprocess
import time
import traceback
from datetime import datetime, timedelta
from math import floor
from urllib.parse import urlparse, parse_qs

from jwkest.jws import JWS
from jwkest.jwt import JWT
from oic import rndstr
from oic.oauth2.message import CCAccessTokenRequest
from oic.oic import Client, Grant, Token, REQUEST2ENDPOINT
from oic.oic.message import (AccessTokenResponse, AuthorizationResponse,
                             Message, RegistrationResponse)
from oic.utils import time_util
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from sqlalchemy import and_
from sqlalchemy.sql.expression import true

from rucio.common.config import config_get, config_get_int
from rucio.common.exception import (CannotAuthenticate, CannotAuthorize,
                                    RucioException)
from rucio.common.utils import all_oidc_req_claims_present, build_url, val_to_space_sep_str
from rucio.core.account import account_exists
from rucio.core.identity import exist_identity_account, get_default_account
from rucio.core.monitor import record_counter, record_timer
from rucio.db.sqla import filter_thread_work
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session

# worokaround for a bug in pyoidc (as of Dec 2019)
REQUEST2ENDPOINT['CCAccessTokenRequest'] = 'token_endpoint'

# private/protected file containing Rucio Client secrets known to the Identity Provider as well
IDPSECRETS = config_get('oidc', 'idpsecrets', False)
ADMIN_ISSUER_ID = config_get('oidc', 'admin_issuer', False)
EXPECTED_OIDC_AUDIENCE = config_get('oidc', 'expected_audience', False, 'rucio')
EXPECTED_OIDC_SCOPE = config_get('oidc', 'expected_scope', False, 'openid profile')
EXCHANGE_GRANT_TYPE = config_get('oidc', 'exchange_grant_type', False, 'urn:ietf:params:oauth:grant-type:token-exchange')
REFRESH_LIFETIME_H = config_get_int('oidc', 'default_jwt_refresh_lifetime', False, 96)

# TO-DO permission layer: if scope == 'wlcg.groups'
# --> check 'profile' info (requested profile scope)


def __get_rucio_oidc_clients(keytimeout=43200):
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
    except:
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
            raise RucioException(error.args)
    return (clients, admin_clients)


# Initialising Rucio OIDC Clients
ALL_OIDC_CLIENTS = __get_rucio_oidc_clients()
OIDC_CLIENTS = ALL_OIDC_CLIENTS[0]
OIDC_ADMIN_CLIENTS = ALL_OIDC_CLIENTS[1]


def __get_init_oidc_client(token_object=None, token_type=None, **kwargs):
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
    try:
        auth_args = {"grant_types": ["authorization_code"],
                     "response_type": "code",
                     "state": kwargs.get('state', rndstr()),
                     "nonce": kwargs.get('nonce', rndstr())}
        auth_args["scope"] = token_object.oidc_scope if token_object else kwargs.get('scope', " ")
        auth_args["audience"] = token_object.audience if token_object else kwargs.get('audience', " ")

        if token_object:
            issuer = token_object.identity.split(", ")[1].split("=")[1]
            oidc_client = OIDC_CLIENTS[issuer]
            auth_args["client_id"] = oidc_client.client_id
            token = ''
            if not token_type:
                token_type = kwargs.get('token_type', None)
            if token_type == 'subject_token':
                token = token_object.token
            if token_type == 'refresh_token':
                token = token_object.refresh_token
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
            except:
                raise CannotAuthenticate("Rucio server is missing information from the idpsecrets.json file.")
            if 'issuer_id' in kwargs:
                client_secret = secrets[kwargs.get('issuer_id', ADMIN_ISSUER_ID)]
            elif 'issuer' in kwargs:
                client_secret = next((secrets[i] for i in secrets if 'issuer' in secrets[i] and  # NOQA: W504
                                      secrets[i]['issuer'] == kwargs.get('issuer')), None)
            redirect_url = kwargs.get('redirect_uri', None)
            if not redirect_url:
                redirect_to = kwargs.get("redirect_to", "auth/oidc_token")
                redirect_urls = [u for u in client_secret["redirect_uris"] if redirect_to in u]
                redirect_url = random.choice(redirect_urls)
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
    except Exception:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_auth_oidc(account, session=None, **kwargs):
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
    # TO-DO - implement a check if that account already has a valid
    # token withthe required scope and audience and return such token !
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
    auto = kwargs.get('auto', False)
    polling = kwargs.get('polling', False)
    refresh_lifetime = kwargs.get('refresh_lifetime', REFRESH_LIFETIME_H)
    ip = kwargs.get('ip', None)
    webhome = kwargs.get('webhome', None)
    # For webui a mock account will be used here and default account
    # will be assigned to the identity during get_token_oidc
    if account.external == 'webui':
        pass
    else:
        # Make sure the account exists
        if not account_exists(account, session=session):
            return None

    try:
        start = time.time()
        # redirect_url needs to be specified & one of those defined
        # in the Rucio OIDC Client configuration
        redirect_to = "auth/oidc_code"
        if auto:
            redirect_to = "auth/oidc_token"
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
        # redirect code is put in access_msg and returned to the user (if auto=False)
        access_msg = None
        if not auto:
            access_msg = rndstr(23)
            if polling:
                access_msg += '_polling'
        if auto and webhome:
            access_msg = str(webhome)
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
        # If user selected authentication via web browser, a redirection
        # URL is returned instead of the direct URL pointing to the IdP.
        if not auto:
            auth_server = urlparse(redirect_url)
            auth_url = build_url('https://' + auth_server.netloc,
                                 path='auth/oidc_redirect', params=access_msg)

        record_counter(counters='IdP_authentication.request')
        record_timer(stat='IdP_authentication.request', time=time.time() - start)
        return auth_url

    except Exception:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_token_oidc(auth_query_string, ip=None, session=None):
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
    try:
        start = time.time()
        parsed_authquery = parse_qs(auth_query_string)
        state = parsed_authquery["state"][0]
        code = parsed_authquery["code"][0]
        # getting oauth request params from the oauth_requests DB Table
        oauth_req_params = session.query(models.OAuthRequest).filter_by(state=state).first()
        if oauth_req_params is None:
            raise CannotAuthenticate("User related Rucio OIDC session could not keep "
                                     + "track of responses from outstanding requests.")  # NOQA: W503
        req_url = urlparse(oauth_req_params.redirect_msg)
        issuer = 'https://' + req_url.netloc + '/'
        req_params = parse_qs(req_url.query)
        for key in req_params:
            req_params[key] = val_to_space_sep_str(req_params[key])

        oidc_client = __get_init_oidc_client(issuer=issuer, code=code, **req_params)['client']
        record_counter(counters='IdP_authentication.code_granted')
        # exchange access code for a access token
        oidc_tokens = oidc_client.do_access_token_request(state=state,
                                                          request_args={"code": code},
                                                          authn_method="client_secret_basic")
        if 'error' in oidc_tokens:
            raise CannotAuthorize(oidc_tokens['error'])
        # mitigate replay attacks
        nonce = oauth_req_params.nonce
        if oidc_tokens['id_token']['nonce'] != nonce:
            raise CannotAuthenticate("ID token could not be associated with the Rucio OIDC Client"
                                     + " session. This points to possible replay attack !")  # NOQA: W503

        # starting to fill dictionary with parameters for token DB row
        jwt_row_dict, extra_dict = {}, {}
        jwt_row_dict['identity'] = oidc_identity_string(oidc_tokens['id_token']['sub'],
                                                        oidc_tokens['id_token']['iss'])
        jwt_row_dict['account'] = oauth_req_params.account

        if jwt_row_dict['account'].external == 'webui':
            try:
                jwt_row_dict['account'] = get_default_account(jwt_row_dict['identity'], IdentityType.OIDC, True, session=session)
            except Exception:
                return {'webhome': None, 'token': None}

        # check if given account has the identity registered
        if not exist_identity_account(jwt_row_dict['identity'], IdentityType.OIDC, jwt_row_dict['account'], session=session):
            raise CannotAuthenticate("OIDC identity '%s' of the '%s' account is unknown to Rucio."
                                     % (jwt_row_dict['identity'], str(jwt_row_dict['account'])))
        record_counter(counters='IdP_authentication.success')
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
            try:
                extra_dict['refresh_lifetime'] = int(oauth_req_params.refresh_lifetime)
            except Exception:
                extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
            try:
                values = __get_keyvalues_from_claims(oidc_tokens['refresh_token'], ['exp'])
                exp = values['exp']
                extra_dict['refresh_expired_at'] = datetime.utcfromtimestamp(float(exp))
            except Exception:
                # 4 day expiry period by default
                extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)

        new_token = __save_validated_token(oidc_tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
        record_counter(counters='IdP_authorization.access_token.saved')
        if 'refresh_token' in oidc_tokens:
            record_counter(counters='IdP_authorization.refresh_token.saved')
        # In case authentication via browser was requested,
        # we save the token in the oauth_requests table
        if oauth_req_params.access_msg:
            # If Rucio Client waits for a fetchcode, we save the token under this code in the DB.
            if 'http' not in oauth_req_params.access_msg:
                if '_polling' not in oauth_req_params.access_msg:
                    fetchcode = rndstr(50)
                    session.query(models.OAuthRequest).filter(models.OAuthRequest.state == state)\
                           .update({models.OAuthRequest.access_msg: fetchcode,
                                    models.OAuthRequest.redirect_msg: new_token['token']})
                # If Rucio Client was requested to poll the Rucio Auth server
                # for a token automatically, we save the token under a access_msg.
                else:
                    session.query(models.OAuthRequest).filter(models.OAuthRequest.state == state)\
                           .update({models.OAuthRequest.access_msg: oauth_req_params.access_msg,
                                    models.OAuthRequest.redirect_msg: new_token['token']})
                session.commit()
            if '_polling' in oauth_req_params.access_msg:
                return {'polling': True}
            elif 'http' in oauth_req_params.access_msg:
                return {'webhome': oauth_req_params.access_msg, 'token': new_token}
            else:
                return {'fetchcode': fetchcode}
        else:
            return {'token': new_token}
        record_timer(stat='IdP_authorization', time=time.time() - start)

    except Exception:
        # TO-DO catch different exceptions - InvalidGrant etc. ...
        record_counter(counters='IdP_authorization.access_token.exception')
        return None
        # raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def __get_admin_token_oidc(account, req_scope, req_audience, issuer, session=None):
    """
    Get a token for Rucio application to act on behalf of itself.
    client_credential flow is used for this purpose.
    No refresh token is expected to be used.

    :param account: the Rucio Admin account name to be used (InternalAccount object expected)
    :param req_scope: the audience requested for the Rucio client's token
    :param req_audience: the scope requested for the Rucio client's token
    :param issuer: the Identity Provider nickname or the Rucio instance in use
    :param session: The database session in use.
    :returns: A dict with token and expires_at entries.
    """
    try:
        oidc_client = OIDC_ADMIN_CLIENTS[issuer]
        args = {"client_id": oidc_client.client_id,
                "client_secret": oidc_client.client_secret,
                "grant_type": "client_credentials",
                "scope": req_scope,
                "audience": req_audience}
        # in the future should use oauth2 pyoidc client (base) instead
        oidc_tokens = oidc_client.do_any(request=CCAccessTokenRequest,
                                         request_args=args,
                                         response=AccessTokenResponse)
        if 'error' in oidc_tokens:
            raise CannotAuthorize(oidc_tokens['error'])
        record_counter(counters='IdP_authentication.rucio_admin_token_granted')
        # save the access token in the Rucio DB
        if 'access_token' in oidc_tokens:
            validate_dict = __get_rucio_jwt_dict(oidc_tokens['access_token'], account=account, session=session)
            if validate_dict:
                record_counter(counters='IdP_authentication.success')
                new_token = __save_validated_token(oidc_tokens['access_token'], validate_dict, extra_dict={}, session=session)
                record_counter(counters='IdP_authorization.access_token.saved')
                return new_token
            return None
            # raise RucioException("Rucio could not get a valid admin token from the Identity Provider.")
        return None
        # raise RucioException("Rucio could not get its admin access token from the Identity Provider.")

    except Exception:
        # TO-DO catch different exceptions - InvalidGrant etc. ...
        record_counter(counters='IdP_authorization.access_token.exception')
        return None
        # raise CannotAuthenticate(traceback.format_exc())


@read_session
def __get_admin_account_for_issuer(session=None):
    """ Gets admin account for the IdP issuer
    :returns : dictionary { 'issuer_1': (account, identity), ... }
    """
    issuer_account_dict = {}
    for issuer in OIDC_ADMIN_CLIENTS:
        admin_identity = oidc_identity_string(OIDC_ADMIN_CLIENTS[issuer].client_id, issuer)
        admin_account = session.query(models.IdentityAccountAssociation)\
                               .filter_by(identity_type=IdentityType.OIDC, identity=admin_identity).first()
        issuer_account_dict[issuer] = (admin_account.account, admin_identity)
    return issuer_account_dict


@transactional_session
def get_token_for_account_operation(account, req_audience=None, req_scope=None, admin=False, session=None):
    """
    Looks-up a JWT token with the required scope and audience claims with the account OIDC issuer.
    If tokens are found, and none contains the requested audience and scope a new token is requested
    (via token exchange or client credential grants in case admin = True)
    :param account: Rucio account name in order to lookup the issuer and corresponding valid tokens
    :param req_audience: audience required to be present in the token (e.g. 'fts:atlas')
    :param req_scope: scope requested to be present in the token (e.g. fts:submit-transfer)
    :param admin: If True tokens will be requested for the Rucio admin root account,
                  preferably with the same issuer as the requesting account OIDC identity
    :param session: DB session in use

    :return: token dictionary or None, throws an exception in case of problems
    """
    try:
        if not req_scope:
            req_scope = EXPECTED_OIDC_SCOPE
        if not req_audience:
            req_audience = EXPECTED_OIDC_AUDIENCE

        # get all identities for the corresponding account
        identities_list = session.query(models.IdentityAccountAssociation.identity) \
                                 .filter(models.IdentityAccountAssociation.identity_type == IdentityType.OIDC,
                                         models.IdentityAccountAssociation.account == account).all()
        identities = []
        for identity in identities_list:
            identities.append(identity[0])
        # get all active/valid OIDC tokens
        account_tokens = session.query(models.Token).filter(models.Token.identity.in_(identities),
                                                            models.Token.account == account,
                                                            models.Token.expired_at > datetime.utcnow()).with_for_update(skip_locked=True).all()

        # for Rucio Admin account we ask IdP for a token via client_credential grant
        # for each user account OIDC identity there is an OIDC issuer that must be, by construction,
        # supported by Rucio server (have OIDC admin client registered as well)
        # that is why we take the issuer of the account identity that has an active/valid token
        # and look for admin account identity which has this issuer assigned
        # requestor should always have at least one active subject token unless it is root
        # this is why we first discover if the requestor is root or not
        get_token_for_adminacc = False
        admin_identity = None
        admin_issuer = None
        admin_iss_acc_idt_dict = __get_admin_account_for_issuer(session=session)

        # check if preferred issuer exists - if multiple present last one is taken
        preferred_issuer = None
        for token in account_tokens:
            preferred_issuer = token.identity.split(", ")[1].split("=")[1]
        # loop through all OIDC identities registerd for the account of the requestor
        for identity in identities:
            issuer = identity.split(", ")[1].split("=")[1]
            # compare the account of the requestor with the account of the admin
            if account == admin_iss_acc_idt_dict[issuer][0]:
                # take first matching case which means root is requesting OIDC authentication
                admin_identity = admin_iss_acc_idt_dict[issuer][1]
                if preferred_issuer and preferred_issuer != issuer:
                    continue
                else:
                    admin_issuer = issuer
                    get_token_for_adminacc = True
                    break

        # Rucio admin account requesting OIDC token
        if get_token_for_adminacc:
            # openid scope is not supported for client_credentials auth flow - removing it if being asked for
            if 'openid' in req_scope:
                req_scope = req_scope.replace("openid", "").strip()
            # checking if there is not already a token to use
            admin_account_tokens = session.query(models.Token).filter(models.Token.account == account,
                                                                      models.Token.expired_at > datetime.utcnow()).all()
            for admin_token in admin_account_tokens:
                if hasattr(admin_token, 'audience') and hasattr(admin_token, 'oidc_scope') and\
                   all_oidc_req_claims_present(admin_token.oidc_scope, admin_token.audience, req_scope, req_audience):
                    return token_dictionary(admin_token)
            # if not found request a new one
            new_admin_token = __get_admin_token_oidc(account, req_scope, req_audience, admin_issuer, session=session)
            return new_admin_token

        # Rucio server requests Rucio user to be represented by Rucio admin OIDC identity
        if admin and not get_token_for_adminacc:
            # we require any other account than admin to have valid OIDC token in the Rucio DB
            if not account_tokens:
                return None
            # we also require that these tokens at least one has the Rucio scopes and audiences
            valid_subject_token_exists = False
            for account_token in account_tokens:
                if all_oidc_req_claims_present(account_token.oidc_scope, account_token.audience, EXPECTED_OIDC_SCOPE, EXPECTED_OIDC_AUDIENCE):
                    valid_subject_token_exists = True
            if not valid_subject_token_exists:
                return None
            # openid scope is not supported for client_credentials auth flow - removing it if being asked for
            if 'openid' in req_scope:
                req_scope = req_scope.replace("openid", "").strip()

            admin_account = None
            for account_token in account_tokens:
                # for each valid account token in the DB we need to check if a valid root token does not exist with the required
                # scope and audience
                admin_issuer = account_token.identity.split(", ")[1].split("=")[1]
                # assuming the requesting account is using Rucio supported IdPs, we check if any token of this admin identity
                # has already a token with the requested scopes and audiences
                admin_acc_idt_tuple = admin_iss_acc_idt_dict[admin_issuer]
                admin_account = admin_acc_idt_tuple[0]
                admin_identity = admin_acc_idt_tuple[1]
                admin_account_tokens = session.query(models.Token).filter(models.Token.identity == admin_identity,
                                                                          models.Token.account == admin_account,
                                                                          models.Token.expired_at > datetime.utcnow()).all()
                for admin_token in admin_account_tokens:
                    if hasattr(admin_token, 'audience') and hasattr(admin_token, 'oidc_scope') and\
                       all_oidc_req_claims_present(admin_token.oidc_scope, admin_token.audience, req_scope, req_audience):
                        return token_dictionary(admin_token)
            # if no admin token existing was found for the issuer of the valid user token
            # we request a new one
            new_admin_token = __get_admin_token_oidc(admin_account, req_scope, req_audience, admin_issuer, session=session)
            return new_admin_token
        # Rucio server requests exchange token for a Rucio user
        if not admin and not get_token_for_adminacc:
            # we require any other account than admin to have valid OIDC token in the Rucio DB
            if not account_tokens:
                return None
            # we also require that these tokens at least one has the Rucio scopes and audiences
            valid_subject_token_exists = False
            for account_token in account_tokens:
                if all_oidc_req_claims_present(account_token.oidc_scope, account_token.audience, EXPECTED_OIDC_SCOPE, EXPECTED_OIDC_AUDIENCE):
                    valid_subject_token_exists = True
            if not valid_subject_token_exists:
                return None
            subject_token = None
            for token in account_tokens:
                if hasattr(token, 'audience') and hasattr(token, 'oidc_scope'):
                    if all_oidc_req_claims_present(token.oidc_scope, token.audience, req_scope, req_audience):
                        return token_dictionary(token)
                # from available tokens select preferentially the one which are being refreshed
                if hasattr(token, 'oidc_scope') and ('offline_access' in str(token['oidc_scope'])):
                    subject_token = token
            # if not proceed with token exchange
            if not subject_token:
                subject_token = random.choice(account_tokens)
            exchanged_token = __exchange_token_oidc(subject_token,
                                                    scope=req_scope,
                                                    audience=req_audience,
                                                    identity=subject_token.identity,
                                                    refresh_lifetime=subject_token.refresh_lifetime,
                                                    account=account,
                                                    session=session)
            return exchanged_token
        return None
    except Exception:
        # raise CannotAuthorize(traceback.format_exc(), type(account), account)
        return None


@transactional_session
def __exchange_token_oidc(subject_token_object, session=None, **kwargs):
    """
    Exchanged an access_token for a new one with different scope &/ audience
    providing that the scope specified is registered with IdP for the Rucio OIDC Client
    and the Rucio user has this scope linked to the subject token presented
    for the token exchange.

    :param subject_token_object: DB subject token to be exchanged
    :param kwargs: 'scope', 'audience', 'grant_type', 'ip' and 'account' doing the exchange
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """
    grant_type = kwargs.get('grant_type', EXCHANGE_GRANT_TYPE)
    jwt_row_dict, extra_dict = {}, {}
    jwt_row_dict['account'] = kwargs.get('account', '')
    jwt_row_dict['authz_scope'] = kwargs.get('scope', '')
    jwt_row_dict['audience'] = kwargs.get('audience', '')
    jwt_row_dict['identity'] = kwargs.get('identity', '')
    extra_dict['ip'] = kwargs.get('ip', None)

    # if subject token has offline access scope but *no* refresh token in the DB
    # (happens when user presents subject token acquired from other sources then Rucio CLI mechanism),
    # add offline_access scope to the token exchange request !
    if 'offline_access' in str(subject_token_object.oidc_scope) and not subject_token_object.refresh_token:
        jwt_row_dict['authz_scope'] += ' offline_access'
    if not grant_type:
        grant_type = EXCHANGE_GRANT_TYPE
    try:
        start = time.time()

        record_counter(counters='IdP_authentication.code_granted')
        oidc_dict = __get_init_oidc_client(token_object=subject_token_object, token_type="subject_token")
        oidc_client = oidc_dict['client']
        args = {"subject_token": subject_token_object.token,
                "scope": jwt_row_dict['authz_scope'],
                "audience": jwt_row_dict['audience'],
                "grant_type": grant_type}
        # exchange , access token for a new one
        oidc_token_response = oidc_dict['client'].do_any(Message,
                                                         endpoint=oidc_client.provider_info["token_endpoint"],
                                                         state=oidc_dict['state'],
                                                         request_args=args,
                                                         authn_method="client_secret_basic")
        oidc_tokens = oidc_token_response.json()
        if 'error' in oidc_tokens:
            raise CannotAuthorize(oidc_tokens['error'])
        # get audience and scope information
        if 'scope' in oidc_tokens and 'audience' in oidc_tokens:
            jwt_row_dict['authz_scope'] = val_to_space_sep_str(oidc_tokens['scope'])
            jwt_row_dict['audience'] = val_to_space_sep_str(oidc_tokens['audience'])
        elif 'access_token' in oidc_tokens:
            values = __get_keyvalues_from_claims(oidc_tokens['access_token'], ['scope', 'aud'])
            jwt_row_dict['authz_scope'] = values['scope']
            jwt_row_dict['audience'] = values['aud']
        jwt_row_dict['lifetime'] = datetime.utcnow() + timedelta(seconds=oidc_tokens['expires_in'])
        if 'refresh_token' in oidc_tokens:
            extra_dict['refresh_token'] = oidc_tokens['refresh_token']
            extra_dict['refresh'] = True
            extra_dict['refresh_lifetime'] = kwargs.get('refresh_lifetime', REFRESH_LIFETIME_H)
            if extra_dict['refresh_lifetime'] is None:
                extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
            try:
                values = __get_keyvalues_from_claims(oidc_tokens['refresh_token'], ['exp'])
                extra_dict['refresh_expired_at'] = datetime.utcfromtimestamp(float(values['exp']))
            except Exception:
                # 4 day expiry period by default
                extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)

        new_token = __save_validated_token(oidc_tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
        record_counter(counters='IdP_authorization.access_token.saved')
        if 'refresh_token' in oidc_tokens:
            record_counter(counters='IdP_authorization.refresh_token.saved')
        record_timer(stat='IdP_authorization.token_exchange', time=time.time() - start)
        return new_token

    except Exception:
        # raise CannotAuthorize(traceback.format_exc())
        return None


@transactional_session
def __change_refresh_state(token, refresh=False, session=None):
    """
    Changes token refresh state to True/False.

    :param token:      the access token for which the refresh value should be changed.
    """
    try:
        if refresh:
            # update refresh column for a token to True
            session.query(models.Token).filter(models.Token.token == token)\
                                       .update({models.Token.refresh: True})
        else:
            session.query(models.Token).filter(models.Token.token == token)\
                                       .update({models.Token.refresh: False,
                                                models.Token.refresh_expired_at: datetime.utcnow()})
        session.commit()
    except Exception as error:
        raise RucioException(error.args)


@transactional_session
def refresh_cli_auth_token(token_string, account, session=None):
    """
    Checks if there is active refresh token and if so returns
    either active token with expiration timestamp or requests a new
    refresh and returns new access token.
    :param token_string: token string
    :param account: Rucio account for which token refresh should be considered

    :return: tuple of (access token, expiration epoch), None otherswise
    """
    # only validated tokens are in the DB, check presence of token_string
    account_token = session.query(models.Token) \
                           .filter(models.Token.token == token_string,
                                   models.Token.account == account,
                                   models.Token.expired_at > datetime.utcnow()) \
                           .with_for_update(skip_locked=True).first()
    # if token does not exist in the DB, return None
    if account_token is None:
        return None

    # protection (!) no further action should be made
    # for token_string without refresh_token in the DB !
    if account_token.refresh_token is None:
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
        new_token = session.query(models.Token) \
                           .filter(models.Token.refresh == true(),
                                   models.Token.refresh_expired_at > datetime.utcnow(),
                                   models.Token.account == account,
                                   models.Token.expired_at > datetime.utcnow()) \
                           .with_for_update(skip_locked=True).first()
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
        return None


@transactional_session
def refresh_jwt_tokens(total_workers, worker_number, refreshrate=3600, limit=1000, session=None):
    """
    Refreshes tokens which expired or will expire before (now + refreshrate)
    next run of this function and which have valid refresh token.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of tokens to refresh per call.
    :param session:            Database session in use.

    :return: numper of tokens refreshed
    """
    nrefreshed = 0
    try:
        # get tokens for refresh that expire in the next <refreshrate> seconds
        expiration_future = datetime.utcnow() + timedelta(seconds=refreshrate)
        query = session.query(models.Token.token) \
                       .filter(and_(models.Token.refresh == true(),
                                    models.Token.refresh_expired_at > datetime.utcnow(),
                                    models.Token.expired_at < expiration_future))\
                       .order_by(models.Token.expired_at)
        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='token')

        # limiting the number of tokens for refresh
        query = query.limit(limit)
        filtered_tokens = []
        for items in session.execute(query).partitions(10):
            tokens = tuple(map(lambda row: row.token, items))
            filtered_tokens += session.query(models.Token) \
                                      .filter(models.Token.token.in_(tokens)) \
                                      .with_for_update(skip_locked=True) \
                                      .all()

        # refreshing these tokens
        for token in filtered_tokens:
            new_token = __refresh_token_oidc(token, session=session)
            if new_token:
                nrefreshed += 1

    except Exception as error:
        raise RucioException(error.args)

    return nrefreshed


@transactional_session
def __refresh_token_oidc(token_object, session=None):
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
        start = time.time()
        record_counter(counters='IdP_authorization.refresh_token.request')
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
        oidc_dict = __get_init_oidc_client(token_object=token_object, token_type="refresh_token")
        oidc_client = oidc_dict['client']
        # getting a new refreshed set of tokens
        state = oidc_dict['state']
        oidc_tokens = oidc_client.do_access_token_refresh(state=state)
        if 'error' in oidc_tokens:
            raise CannotAuthorize(oidc_tokens['error'])
        record_counter(counters='IdP_authorization.refresh_token.refreshed')
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
            record_counter(counters='IdP_authorization.access_token.saved')
            record_counter(counters='IdP_authorization.refresh_token.saved')
        else:
            raise CannotAuthorize("OIDC identity '%s' of the '%s' account is did not " % (token_object.identity, token_object.account)
                                  + "succeed requesting a new access and refresh tokens.")  # NOQA: W503
        record_timer(stat='IdP_authorization.refresh_token', time=time.time() - start)
        return new_token

    except Exception:
        record_counter(counters='IdP_authorization.refresh_token.exception')
        raise CannotAuthorize(traceback.format_exc())


@transactional_session
def delete_expired_oauthrequests(total_workers, worker_number, limit=1000, session=None):
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
        query = session.query(models.OAuthRequest.state).filter(models.OAuthRequest.expired_at < datetime.utcnow())\
                       .order_by(models.OAuthRequest.expired_at)

        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='state')

        # limiting the number of oauth requests deleted at once
        query = query.limit(limit)
        ndeleted = 0
        for items in session.execute(query).partitions(10):
            states = tuple(map(lambda row: row.state, items))
            ndeleted += session.query(models.OAuthRequest) \
                               .filter(models.OAuthRequest.state.in_(states)) \
                               .with_for_update(skip_locked=True) \
                               .delete(synchronize_session='fetch')

    except Exception as error:
        raise RucioException(error.args)

    return ndeleted


def __get_keyvalues_from_claims(token, keys=None):
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
                value = val_to_space_sep_str(claims[key])
            resdict[key] = value
        return resdict
    except Exception:
        raise CannotAuthenticate(traceback.format_exc())


@read_session
def __get_rucio_jwt_dict(jwt, account=None, session=None):
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
                return None
        value = {'account': account,
                 'identity': identity_string,
                 'lifetime': expiry_date,
                 'audience': audience,
                 'authz_scope': scope}
        return value
    except Exception:
        return None


@transactional_session
def __save_validated_token(token, valid_dict, extra_dict=None, session=None):
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
        raise RucioException(error.args)


@transactional_session
def validate_jwt(json_web_token, session=None):
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
              if successful, None otherwise.
    """
    try:
        # getting issuer from the token payload
        token_dict = __get_rucio_jwt_dict(json_web_token, session=session)
        if not token_dict:
            return None
        issuer = token_dict['identity'].split(", ")[1].split("=")[1]
        oidc_client = OIDC_CLIENTS[issuer]
        issuer_keys = oidc_client.keyjar.get_issuer_keys(issuer)
        JWS().verify_compact(json_web_token, issuer_keys)
        # if there is no audience and scope information,
        # try to get it from IdP introspection endpoint
        # TO-BE-REMOVED - once all IdPs support scope and audience in token claims !!!
        if not token_dict['authz_scope'] or not token_dict['audience']:
            clprocess = subprocess.Popen(['curl', '-s', '-L', '-u', '%s:%s'
                                          % (oidc_client.client_id, oidc_client.client_secret),
                                          '-d', 'token=%s' % (json_web_token),
                                          oidc_client.introspection_endpoint],
                                         shell=False, stdout=subprocess.PIPE)
            inspect_claims = json.loads(clprocess.communicate()[0])
            try:
                token_dict['audience'] = inspect_claims['aud']
                token_dict['authz_scope'] = inspect_claims['scope']
            except:
                pass
        record_counter(counters='JSONWebToken.valid')
        # if token is valid and coming from known issuer --> check aud and scope and save it if unknown
        if token_dict['authz_scope'] and token_dict['audience']:
            if all_oidc_req_claims_present(token_dict['authz_scope'], token_dict['audience'], EXPECTED_OIDC_SCOPE, EXPECTED_OIDC_AUDIENCE):
                # save the token in Rucio DB giving the permission to use it for Rucio operations
                __save_validated_token(json_web_token, token_dict, session=session)
            else:
                return None
        else:
            return None
        record_counter(counters='JSONWebToken.saved')
        return token_dict
    except Exception:
        record_counter(counters='JSONWebToken.invalid')
        return None


def oidc_identity_string(sub, iss):
    """
    Transform IdP sub claim and issuers url into users identity string.
    :param sub: users SUB claim from the Identity Provider
    :param iss: issuer (IdP) https url

    :returns: OIDC identity string "SUB=<usersid>, ISS=https://iam-test.ch/"
    """
    return 'SUB=' + str(sub) + ', ISS=' + str(iss)


def token_dictionary(token: models.Token):
    return {'token': token.token, 'expires_at': token.expired_at}
