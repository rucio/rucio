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
# - Martin Barisits <martin.barisits@cern.ch>, 2012-2019
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2017
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
#
# PY3K COMPATIBLE

import base64
import datetime
import hashlib
import random
import sys
import traceback
import json
import time

import paramiko

from sqlalchemy import or_, and_
from sqlalchemy.sql.expression import bindparam, text, true, false

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE

from rucio.common.exception import RucioException, CannotAuthenticate, CannotAuthorize, CannotInitOIDCClient
from rucio.common.utils import generate_uuid, oidc_identity_string, build_url
from rucio.common.types import InternalAccount
from rucio.core.account import account_exists
from rucio.core.monitor import record_counter, record_timer
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session
from rucio.core.identity import get_default_account

from oic import rndstr
from oic.oic import Client, Grant, Token
from oic.utils import time_util
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oic.message import RegistrationResponse, AuthorizationResponse, AccessTokenResponse, Message
from jwkest.jws import JWS
from jwkest.jwt import JWT

try:
    # Python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qs


def token_key_generator(namespace, fni, **kwargs):
    """ :returns: generate key function """
    def generate_key(token, session=None):
        """ :returns: token """
        return token
    return generate_key


TOKENREGION = make_region(
    function_key_generator=token_key_generator
).configure(
    'dogpile.cache.memory',
    expiration_time=3600
)

# private/protected file containing Rucio Client secrets known to the Identity Provider as well
idpsecrets = '/opt/rucio/etc/idpsecrets.json'

# TO-DO permission layer: if scope == 'wlcg.groups'
# --> check 'profile' info (requested profile scope)
# decide on exchanges permitted and save the dict per token in the DB
# (user groups maybe need to be transformed in to exchange token patameters
# and the permitted token echange audience and scopes to be saved in the DB table as well)
exchange_params = {
    'audiences': {'rucio': 'fts'},
    'scopes': {}
}


@read_session
def exist_identity_account(identity, type, account, session=None):
    """
    Check if an identity is mapped to an account.

    :param identity: The user identity as string.
    :param type: The type of identity as a string, e.g. userpass, x509, gss, oidc...
    :param account: The account identifier as a string.
    :param session: The database session in use.

    :returns: True if identity is mapped to account, otherwise False
    """

    return session.query(models.IdentityAccountAssociation).filter_by(identity=identity,
                                                                      identity_type=type,
                                                                      account=account).first() is not None


def partition_load(query, column_name, total_workers, worker_number, session=None):
    """
    Adds filter to a DB session query in order to distribute
    the queried number of rows among all workers.
    :param total_workers: total number of threads started
    :param worker_number: the number of the worker asking for query results
    :param column: name of the column w.r.t. which the partitioning should be made
    :param query: the session query

    :returns: session query in case all went OK, Exception otherwise.

    """
    try:
        if worker_number and total_workers and total_workers - 1 > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('worker_number', worker_number - 1), bindparam('total_workers', total_workers - 1)]
                query = query.filter(text('ORA_HASH(%s, :total_workers) = :worker_number' % column_name, bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter(text('mod(md5(%s), %s) = %s' % (column_name, total_workers - 1, worker_number - 1)))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter(text('mod(abs((\'x\'||md5(%s))::bit(32)::int), %s) = %s' % (column_name, total_workers - 1, worker_number - 1)))

        return query

    except Exception as error:
        raise RucioException(error.args)


def get_rucio_OIDC_clients():
    """
    Creates a Rucio OIDC Client instances as defined per Identity Provider (IdP) in the
    etc/idpsecrets.json configuration file. These have to be pre-registered with the
    respective IdP with the appropriate settings.
    (allowed to request refresh tokens, token exchange, immediate refresh tokens expiration
    after first use, refresh tokens have lifetime set in their unverified header)

    :returns: Dictionary of {'https://issuer_1/': <Rucio OIDC Client_1 instance>,
              'https://issuer_2/': <Rucio OIDC Client_2 instance>,}.
              In case of trouble, Exception is raised.
    """
    # initializing a client_id and client_secret - provided in a secret config file
    with open(idpsecrets) as client_secret_file:
        client_secrets = json.load(client_secret_file)
    clients = {}
    for iss in client_secrets:
        try:
            client_secret = client_secrets[iss]
            issuer = client_secret["issuer"]
            client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
            # general parameter discovery about the Identity Provider via the issuers URL
            client.provider_config(issuer)
            # transforming Rucio OIDC Client specific parameters into a registration form
            client_reg = RegistrationResponse(**client_secret)
            # storing such parameters (client_id, client_secret, etc.) into the client itself
            client.store_registration_info(client_reg)
            clients[issuer] = client
        except:
            raise CannotInitOIDCClient(traceback.format_exc())
    return clients


# Initialising Rucio OIDC Clients
OIDC_clients = get_rucio_OIDC_clients()


@transactional_session
def get_auth_token_user_pass(account, username, password, appid, ip=None, session=None):
    """
    Authenticate a Rucio account temporarily via username and password.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client a a string.
    :param session: The database session in use.

    :returns: Authentication token as a Python struct
              .token string
              .expired_at datetime
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    result = session.query(models.Identity).filter_by(identity=username,
                                                      identity_type=IdentityType.USERPASS).first()

    db_salt = result['salt']
    db_password = result['password']
    if db_password != hashlib.sha256('%s%s' % (db_salt, password)).hexdigest():
        return None

    # get account identifier
    result = session.query(models.IdentityAccountAssociation).filter_by(identity=username,
                                                                        identity_type=IdentityType.USERPASS,
                                                                        account=account).first()
    db_account = result['account']

    # remove expired tokens
    session.query(models.Token).filter(models.Token.expired_at < datetime.datetime.utcnow(),
                                       models.Token.account == account).with_for_update(skip_locked=True).delete()

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = '%(account)s-%(username)s-%(appid)s-%(tuid)s' % locals()
    new_token = models.Token(account=db_account, token=token, ip=ip)
    new_token.save(session=session)
    session.expunge(new_token)

    return new_token


@read_session
def redirect_auth_OIDC(auth_code, fetchtoken=False, session=None):
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
    try:
        redirect_result = session.query(models.OAuthRequest.redirect_msg).filter_by(redirect_code=auth_code).first()

        if isinstance(redirect_result, tuple):
            if 'http' not in redirect_result[0] and fetchtoken:
                # in this case the function check if the value is a valid token
                v = validate_auth_token(redirect_result[0])
                if not v:
                    return None
                else:
                    return redirect_result[0]
            elif 'http' in redirect_result[0] and not fetchtoken:
                # return redirection URL
                return redirect_result[0]
            else:
                return None
        return None
    except:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_auth_OIDC(account, session=None, **kwargs):
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
    auth_scope = kwargs.get('auth_scope', 'openid')
    audience = kwargs.get('audience', 'rucio')
    issuer = kwargs.get('issuer', 'xdc')
    auto = kwargs.get('auto', False)
    polling = kwargs.get('polling', False)
    refresh_lifetime = kwargs.get('refresh_lifetime', 96)
    ip = kwargs.get('ip', None)
    global OIDC_clients

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    try:
        start = time.time()
        # get the redirect URIs (they have to be included in Rucio OIDC Client configuration)
        with open(idpsecrets) as client_secret_file:
            client_secret = json.load(client_secret_file)
        client_secret = client_secret[issuer]
        issuer = client_secret["issuer"]
        OIDC_client = OIDC_clients[issuer]
        # redirect_url needs to be specified & one of those defined in the Rucio OIDC Client configuration
        redirect_url = None
        rucio_rest_endpoint = "auth/OIDC_code"
        if auto:
            rucio_rest_endpoint = "auth/OIDC_token"
        redirect_urls = [url for url in client_secret["redirect_uris"] if rucio_rest_endpoint in url]
        if len(redirect_urls) >= 1:
            # take random server if more choices
            redirect_url = random.choice(redirect_urls)
        else:
            raise CannotAuthenticate('Could not pick any redirect URL(s) from the ones defined in Rucio OIDC Client configuration file.')

        # user_session_state: random string in order to keep track of responses to outstanding requests (state).
        user_session_state = rndstr(50)
        # user_session_nonce: random string in order to associate a client session with an ID Token and to mitigate replay attacks.
        user_session_nonce = rndstr(50)
        # Assembling the Rucio user related auth URL to be returned to the user
        auth_args = {"client_id": OIDC_client.client_id,
                     "grant_types": ["authorization_code"],
                     "response_type": "code",
                     "scope": auth_scope,
                     "nonce": user_session_nonce,
                     "audience": audience,
                     "redirect_uri": redirect_url,
                     "state": user_session_state}
        auth_req = OIDC_client.construct_AuthorizationRequest(request_args=auth_args)
        auth_url = auth_req.request(OIDC_client.authorization_endpoint)
        # redirect code is used by the user to redirect him/her to the IdP login page
        # via Rucio Auth Server in case he/she did not trust Rucio Client with his/her IdP credentials
        redirect_code = None
        if not auto:
            redirect_code = rndstr(23)
            if polling:
                redirect_code += '_polling'
        # Making sure refresh_lifetime is an integer or None.
        if refresh_lifetime:
            refresh_lifetime = int(refresh_lifetime)
        # Specifying 10 min lifetime for the authentication session (should not be too long).
        expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=600)
        # saving session parameters into the Rucio DB
        oauth_session_params = models.OAuthRequest(account=account,
                                                   state=user_session_state,
                                                   nonce=user_session_nonce,
                                                   redirect_code=redirect_code,
                                                   redirect_msg=auth_url,
                                                   expired_at=expired_at,
                                                   refresh_lifetime=refresh_lifetime,
                                                   ip=ip)
        oauth_session_params.save(session=session)
        session.expunge(oauth_session_params)
        # If user selected authentication via web browser, a redirection URL is returned instead of the direct URL pointing to the IdP.
        if not auto:
            auth_server = urlparse(redirect_url)
            auth_url = build_url('https://' + auth_server.netloc, path='auth/OIDC_redirect', params=redirect_code)

        record_counter(counters='IdP_authentication.request')
        record_timer(stat='IdP_authentication.request', time=time.time() - start)
        return auth_url

    except:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_token_OIDC(auth_query_string, ip=None, session=None):
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
    global OIDC_clients
    try:
        start = time.time()
        # first we lookup session state in the oauth_requests DB table to get the issuer
        parsed_authquery = parse_qs(auth_query_string)
        state = parsed_authquery["state"][0]
        code = parsed_authquery["code"][0]
        # check continuity of the requests
        result = session.query(models.OAuthRequest).filter_by(state=state).first()
        if result is None:
            raise CannotAuthenticate("User related Rucio OIDC session could not" +
                                     "keep track of responses from outstanding requests.")

        redirect_msg = result.redirect_msg
        # getting the issuer string
        authn_url = urlparse(redirect_msg)
        issuer = authn_url.scheme + '://' + authn_url.netloc + '/'
        # get the appropriate Rucio OIDC client
        OIDC_client = OIDC_clients[issuer]

        # extract other parameters of the original authentication request
        account = result.account
        nonce = result.nonce
        redirect_code = result.redirect_code
        refresh_lifetime = result.refresh_lifetime
        auth_args = parse_qs(authn_url.query)
        auth_args["grant_types"] = ["authorization_code"]

        # re-initializing authentication request info in OIDC client (to make it work on multiple server instances)
        OIDC_client.authorization_request_info(request_args=auth_args)
        # parsing the authorization query string by the Rucio OIDC Client
        OIDC_client.parse_response(AuthorizationResponse,
                                   info=auth_query_string,
                                   sformat="urlencoded")
        # assembling parameters to request an access token

        args = {"code": code,
                "audience": auth_args['audience'],
                "scope": auth_args['scope'],
                }
        record_counter(counters='IdP_authentication.code_granted')

        # exchange access code for a access token
        oidc_tokens = OIDC_client.do_access_token_request(state=state,
                                                          request_args=args,
                                                          authn_method="client_secret_basic")
        # mitigate replay attacks
        ID_token_nonce = oidc_tokens['id_token']['nonce']
        if ID_token_nonce != nonce:
            raise CannotAuthenticate("ID token could not be associated with the Rucio OIDC Client session." +
                                     " This points to possible replay attack !")

        # recognize Rucio account using the OIDC identity string
        identity_string = oidc_identity_string(oidc_tokens['id_token']['sub'], oidc_tokens['id_token']['iss'])
        # check if given account has the identity registered
        if session.query(models.IdentityAccountAssociation).filter_by(identity=identity_string,
                                                                      identity_type=IdentityType.OIDC,
                                                                      account=account).first() is None:
            raise CannotAuthenticate("OIDC identity '%s' of the '%s' account is unknown to Rucio." % (identity_string, account))

        record_counter(counters='IdP_authentication.success')
        # get access token expiry timestamp
        expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=oidc_tokens['expires_in'])
        # get audience and group information (assumes profile scope is provided) from id_token
        audience = " ".join(auth_args['audience'])
        at_claims = json.loads(JWT().unpack(oidc_tokens['access_token']).part[1])
        if 'aud' in at_claims:
            audience = at_claims['aud']
        # groups = oidc_tokens['id_token']['groups']
        # nothing done with group info for the moment - TO-DO !
        if isinstance(oidc_tokens['scope'], list):
            scope = " ".join(oidc_tokens['scope'])
        else:
            scope = oidc_tokens['scope']
        # In case user requested to grant Rucio a refresh token, this token will get saved in the DB
        # and an automatic refresh for a specified period of time will be initiated (done by the Rucio daemon).
        if 'refresh_token' in oidc_tokens:
            # save refresh and access tokens in the DB
            if refresh_lifetime:
                refresh_lifetime = int(refresh_lifetime)
            else:
                refresh_lifetime = 96
            try:
                exp = json.loads(JWT().unpack(oidc_tokens['refresh_token']).part[1])['exp']
                refresh_expired_at = datetime.datetime.utcfromtimestamp(exp)
            except:
                # 4 day expiry period by default
                refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(hours=96)

            new_token = models.Token(account=account,
                                     token=oidc_tokens['access_token'],
                                     refresh_token=oidc_tokens['refresh_token'],
                                     scope=scope,
                                     refresh=True,
                                     audience=audience,
                                     expired_at=expired_at,
                                     refresh_expired_at=refresh_expired_at,
                                     refresh_lifetime=refresh_lifetime,
                                     identity=identity_string,
                                     ip=ip)
            new_token.save(session=session)
            session.expunge(new_token)
            record_counter(counters='IdP_authorization.access_token.saved')
            record_counter(counters='IdP_authorization.refresh_token.saved')
            # remove refresh token info (not for the user/Rucio Client)
            new_token.refresh_token = None
            new_token.refresh_expired_at = None

        else:
            # return an access token
            new_token = models.Token(account=account,
                                     token=oidc_tokens['access_token'],
                                     scope=scope,
                                     refresh=False,
                                     expired_at=expired_at,
                                     audience=audience,
                                     identity=identity_string,
                                     ip=ip)
            new_token.save(session=session)
            session.expunge(new_token)
            record_counter(counters='IdP_authorization.access_token.saved')

        # In case authentication via browser was requested, we save the token temporarily in the oauth_requests table
        if redirect_code:

            # If Rucio Client waits for a fetchcode, we save the token under this code in the DB.
            if '_polling' not in redirect_code:
                fetchcode = rndstr(50)
                session.query(models.OAuthRequest).filter(models.OAuthRequest.state == state)\
                       .update({models.OAuthRequest.redirect_code: fetchcode,
                                models.OAuthRequest.redirect_msg: new_token.token})
            # If Rucio Client was requested to poll the Rucio Auth server for a token automatically, we save the token under a redirect_code.
            else:
                session.query(models.OAuthRequest).filter(models.OAuthRequest.state == state)\
                       .update({models.OAuthRequest.redirect_code: redirect_code,
                                models.OAuthRequest.redirect_msg: new_token.token})
            session.commit()
            if '_polling' in redirect_code:
                return ('polling', True)
            else:
                return ('fetchcode', fetchcode)
        else:
            return ('token', new_token)
        record_timer(stat='IdP_authorization', time=time.time() - start)

    except:
        # TO-DO catch different exceptions - InvalidGrant etc. ...
        record_counter(counters='IdP_authorization.access_token.exception')
        raise CannotAuthenticate(traceback.format_exc())


@read_session
def get_account_jwt_for_operation(account, req_audience, req_scope=None, session=None):
    """
    Looks-up the token in the DB, reads scope and audience parameters and decides
    which exchange should be made or returns None in case authorization is missing.
    :param token_string: Token to be exchanged for a new one
    :param session: DB session in use

    :return: Token or None, throws an exception in case of problems
    """
    try:
        # get the OIDC identities of the account
        account = InternalAccount(account)
        identities = session.query(models.IdentityAccountAssociation.identity)\
                            .filter_by(identity_type=IdentityType.OIDC, account=account).all()
        # check if there is no exchange token with the requested parameters already in the DB
        account_tokens = session.query(models.Token).filter(models.Token.identity.in_(identities),
                                                            models.Token.account == account,
                                                            models.Token.expired_at > datetime.datetime.utcnow()).all()
        if len(account_tokens) < 1:
            raise CannotAuthorize("Rucio could not exchange the subject token since it did not find any valid token associated with OIDC identity of account %s" % account)
        # from available accounts select preferentially the one which
        # is being refreshed (offline_access in the scope)
        subject_token = None
        for token in account_tokens:
            if token.audience:
                if req_audience in token.audience:
                    return token
            if 'offline_access' in token.scope:
                subject_token = token
        if not subject_token:
            subject_token = random.choice(account_tokens)

        if not req_scope:
            req_scope = subject_token.scope

        exchange_audience = [exchange_params['audiences'][i] for i in exchange_params['audiences'] if token.audience == i and req_audience in exchange_params['audiences'][i]]
        exchange_scope = [exchange_params['scopes'][i] for i in exchange_params['scopes'] if token.scope == i and req_scope in exchange_params['scopes'][i]]
        if not exchange_scope:
            exchange_scope = subject_token.scope
        else:
            exchange_scope = exchange_scope[0]
        if not exchange_audience:
            exchange_audience = subject_token.audience
        else:
            exchange_audience = exchange_audience[0]
        if subject_token.audience != exchange_audience or subject_token.scope != exchange_scope:
            exchanged_token = exchange_token_OIDC(subject_token.token, exchange_scope, exchange_audience, grant_type=None, refresh_lifetime=subject_token.refresh_lifetime)
            return exchanged_token
        else:
            return None
    except:
        raise CannotAuthorize("Rucio could not exchange the subject token:\n %s" % traceback.format_exc())


@transactional_session
def exchange_token_OIDC(subject_token, scope, audience, grant_type=None, refresh_lifetime=None, session=None):
    """
    An access_token can be exchanged for a new one with different scope &/ audience
    providing that the scope specified is registered with IdP for the Rucio OIDC Client
    and the Rucio user has this scope linked to the subject token presented
    for the token exchange, listed for XDC IAM e.g. here:
    curl -H "Authorization: Bearer ..." https://iam.example/api/scopes
    The new scopes to request must be always in the original token
    (asking for more restrictive token than the original one).

    :param subject_token: subject token to be exchanged
    :param scope: scope to be defined in the new token
    :param audience: audience to be defined in the new token
    :param grant_type: is made a parameter, only because IdP could change this long
                       string in the future to just 'token_exchange' or similar
    :param session: The database session in use.

    :returns: new DB access token table object
    """
    if not grant_type:
        grant_type = "urn:ietf:params:oauth:grant-type:token-exchange"
    global OIDC_clients
    try:
        start = time.time()

        record_counter(counters='IdP_authentication.code_granted')
        # Validate the subject token
        validated = validate_auth_token(subject_token)
        if not validated:
            raise CannotAuthenticate("The subject token presented for the token exchange is invalid.")
        # Get the token issuer from the token payload
        issuer = JWT().unpack(subject_token).payload()['iss']
        OIDC_client = OIDC_clients[issuer]
        # create a grant instance of the OIDC_client
        exchange_session_state = rndstr(50)
        OIDC_client.grant[exchange_session_state] = Grant()
        OIDC_client.grant[exchange_session_state].grant_expiration_time = time_util.utc_time_sans_frac() + 60
        OIDC_client.grant[exchange_session_state].code = "exchange_code"
        resp = AccessTokenResponse()
        resp["subject_token"] = subject_token
        OIDC_client.grant[exchange_session_state].tokens.append(Token(resp))

        # assembling parameters to request a new access token
        args = {"subject_token": subject_token,
                "scope": scope,
                "audience": audience,
                "grant_type": grant_type}
        print(args, OIDC_client.provider_info["token_endpoint"], exchange_session_state, )
        # exchange access code for a access token
        oidc_token_response = OIDC_client.do_any(Message,
                                                 endpoint=OIDC_client.provider_info["token_endpoint"],
                                                 state=exchange_session_state,
                                                 request_args=args,
                                                 authn_method="client_secret_basic")
        oidc_tokens = oidc_token_response.json()
        if isinstance(oidc_tokens['scope'], list):
            scope = " ".join(oidc_tokens['scope'])
        else:
            scope = oidc_tokens['scope']
        expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=oidc_tokens['expires_in'])
        if 'refresh_token' in oidc_tokens:
            # save the received access and refresh tokens in the DB
            if refresh_lifetime:
                refresh_lifetime = int(refresh_lifetime)
            else:
                refresh_lifetime = 96
            try:
                exp = json.loads(JWT().unpack(oidc_tokens['refresh_token']).part[1])['exp']
                refresh_expired_at = datetime.datetime.utcfromtimestamp(exp)
            except:
                # 4 day expiry period by default
                refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(hours=96)

            new_token = models.Token(account=validated['account'],
                                     token=oidc_tokens['access_token'],
                                     refresh_token=oidc_tokens['refresh_token'],
                                     scope=scope,
                                     refresh=True,
                                     audience=audience,
                                     expired_at=expired_at,
                                     refresh_expired_at=refresh_expired_at,
                                     refresh_lifetime=refresh_lifetime,
                                     identity=validated['identity'])
            new_token.save(session=session)
            session.expunge(new_token)
            record_counter(counters='IdP_authorization.access_token.saved')
            record_counter(counters='IdP_authorization.refresh_token.saved')
            # remove refresh token info (not for the user/Rucio Client)
            new_token.refresh_token = None
            new_token.refresh_expired_at = None
        else:
            # save the received access token in the DB
            new_token = models.Token(account=validated['account'],
                                     token=oidc_tokens['access_token'],
                                     scope=scope,
                                     refresh=False,
                                     expired_at=expired_at,
                                     audience=audience,
                                     identity=validated['identity'])
            new_token.save(session=session)
            session.expunge(new_token)
        record_counter(counters='IdP_authorization.exchange_token.saved')
        record_timer(stat='IdP_authorization.exchange_token', time=time.time() - start)
        return new_token

    except:
        raise CannotAuthorize(traceback.format_exc())
        return None


@transactional_session
def refresh_token_OIDC(token_object, session=None):
    """
    Requests new access and refresh tokens from the Identity Provider.
    Assumption: The Identity Provider issues refresh tokens for one time use only and
    with a limited lifetime. The refresh tokens are invalidated no matter which of these
    situations happens first.

    :param token_object: Rucio models.Token DB row object

    :returns: None or throws an Exception.
    """
    global OIDC_clients
    try:
        start = time.time()
        record_counter(counters='IdP_authorization.refresh_token.request')
        refresh_start = datetime.datetime.utcnow()
        # check if refresh token started in the past already
        if hasattr(token_object, 'refresh_start'):
            if token_object.refresh_start:
                refresh_start = token_object.refresh_start
        # check if refresh lifetime is set for the token
        refresh_lifetime = 96
        if token_object.refresh_lifetime:
            refresh_lifetime = token_object.refresh_lifetime
        # if the token has been refreshed for time exceeding the refresh_lifetime, the attempt will be aborted and refresh stopped
        if (datetime.datetime.utcnow() - refresh_start > datetime.timedelta(hours=refresh_lifetime)):
            # abort further refresh attempts
            session.query(models.Token).filter(models.Token.token == token_object.token).update({models.Token.refresh: False})
            session.commit()
            raise CannotAuthorize("Rucio aborted refresh token attempts due to exceeding max refresh limit of %i hours." % refresh_lifetime)

        # checking the expiry date of the refresh token
        if (token_object.refresh_expired_at is None) or (not token_object.refresh_expired_at > datetime.datetime.utcnow()):
            raise CannotAuthorize("Rucio aborted refresh token attempts due to an attempt to use expired refresh token.")

        # get the issuer from the token payload
        issuer = JWT().unpack(token_object.token).payload()['iss']
        OIDC_client = OIDC_clients[issuer]
        # assemble the request for the refresh token from the Identity Provider
        refresh_session_state = rndstr(50)
        OIDC_client.grant[refresh_session_state] = Grant()
        OIDC_client.grant[refresh_session_state].grant_expiration_time = time_util.utc_time_sans_frac() + 60
        OIDC_client.grant[refresh_session_state].code = "access_code"
        resp = AccessTokenResponse()
        resp["refresh_token"] = token_object.refresh_token
        OIDC_client.grant[refresh_session_state].tokens.append(Token(resp))
        # if request below is successful, the used refresh token is assumed to become automatically invalid on the side of IAM (Identity Provider)
        oidc_tokens = OIDC_client.do_access_token_refresh(state=refresh_session_state)
        record_counter(counters='IdP_authorization.refresh_token.refreshed')
        # get audience and group information (assumes profile scope is provided) from id_token
        audience = token_object.audience
        at_claims = json.loads(JWT().unpack(oidc_tokens['access_token']).part[1])
        if 'aud' in at_claims:
            audience = at_claims['aud']
        # groups = oidc_tokens['id_token']['groups']
        # nothing done with group info for the moment - TO-DO !

        # save new access and refresh tokens in the DB
        if isinstance(oidc_tokens['scope'], list):
            scope = " ".join(oidc_tokens['scope'])
        else:
            scope = oidc_tokens['scope']
        if 'refresh_token' in oidc_tokens and 'access_token' in oidc_tokens:
            # aborting refresh of the original token (keeping it in place until it expires) and setting the expiry time of the refresh token to now
            session.query(models.Token).filter(models.Token.token == token_object.token)\
                   .update({models.Token.refresh: False, models.Token.refresh_expired_at: datetime.datetime.utcnow()})
            session.commit()

            # get access token expiry timestamp
            expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=oidc_tokens['expires_in'])

            try:
                exp = json.loads(JWT().unpack(oidc_tokens['refresh_token']).part[1])['exp']
                refresh_expired_at = datetime.datetime.utcfromtimestamp(exp)
            except:
                # 4 day expiry period by default
                refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(hours=96)

            new_token = models.Token(account=token_object.account,
                                     token=oidc_tokens['access_token'],
                                     refresh_token=oidc_tokens['refresh_token'],
                                     scope=scope,
                                     audience=audience,
                                     refresh=True,
                                     expired_at=expired_at,
                                     refresh_expired_at=refresh_expired_at,
                                     refresh_start=refresh_start,
                                     refresh_lifetime=refresh_lifetime,
                                     identity=token_object.identity)
            new_token.save(session=session)
            session.expunge(new_token)
            record_counter(counters='IdP_authorization.access_token.saved')
            record_counter(counters='IdP_authorization.refresh_token.saved')
            # remove refresh token info (not for the user)
            new_token.refresh_token = None
            new_token.refresh_expired_at = None

        else:
            raise CannotAuthorize("OIDC identity '%s' of the '%s' account is did not succeed requesting a new access and refresh tokens." % (token_object.identity, token_object.account))
        record_timer(stat='IdP_authorization.refresh_token', time=time.time() - start)
        return None

    except:
        record_counter(counters='IdP_authorization.refresh_token.exception')
        raise CannotAuthorize(traceback.format_exc())


@transactional_session
def get_auth_token_x509(account, dn, appid, ip=None, session=None):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param id: The application identifier as a string.
    :param ipaddr: IP address of the client as a string.
    :param session: The database session in use.

    :returns: Authentication token as a Python struct
              .token string
              .expired_at datetime
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # remove expired tokens
    session.query(models.Token).filter(models.Token.expired_at < datetime.datetime.utcnow(),
                                       models.Token.account == account).with_for_update(skip_locked=True).delete()

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = '%(account)s-%(dn)s-%(appid)s-%(tuid)s' % locals()
    new_token = models.Token(account=account, token=token, ip=ip)
    new_token.save(session=session)
    session.expunge(new_token)

    return new_token


@transactional_session
def get_auth_token_gss(account, gsstoken, appid, ip=None, session=None):
    """
    Authenticate a Rucio account temporarily via a GSS token.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param gsscred: GSS principal@REALM as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: Authentication token as a Python struct
              .token string
              .expired_at datetime
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # remove expired tokens
    session.query(models.Token).filter(models.Token.expired_at < datetime.datetime.utcnow(),
                                       models.Token.account == account).with_for_update(skip_locked=True).delete()

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = '%(account)s-%(gsstoken)s-%(appid)s-%(tuid)s' % locals()
    new_token = models.Token(account=account, token=token, ip=ip)
    new_token.save(session=session)
    session.expunge(new_token)

    return new_token


@transactional_session
def get_auth_token_ssh(account, signature, appid, ip=None, session=None):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param signature: Response to server challenge signed with SSH private key as string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: Authentication token as a Python struct
              .token string
              .expired_at datetime
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # get all active challenge tokens for the requested account
    active_challenge_tokens = session.query(models.Token).filter(models.Token.expired_at >= datetime.datetime.utcnow(),
                                                                 models.Token.account == account,
                                                                 models.Token.token.like('challenge-%')).all()

    # get all identities for the requested account
    identities = session.query(models.IdentityAccountAssociation).filter_by(identity_type=IdentityType.SSH,
                                                                            account=account).all()

    # no challenge tokens found
    if not active_challenge_tokens:
        return None

    # try all available SSH identities for the account with the provided signature
    match = False
    for identity in identities:
        pub_k = paramiko.RSAKey(data=base64.b64decode(identity['identity'].split()[1]))
        for challenge_token in active_challenge_tokens:
            if pub_k.verify_ssh_sig(str(challenge_token['token']),
                                    paramiko.Message(signature)):
                match = True
                break
        if match:
            break

    if not match:
        return None

    # remove expired tokens
    session.query(models.Token).filter(models.Token.expired_at < datetime.datetime.utcnow(),
                                       models.Token.account == account).with_for_update(skip_locked=True).delete()

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = '%(account)s-ssh:pubkey-%(appid)s-%(tuid)s' % locals()
    new_token = models.Token(account=account, token=token, ip=ip)
    new_token.save(session=session)
    session.expunge(new_token)

    return new_token


@transactional_session
def get_ssh_challenge_token(account, appid, ip=None, session=None):
    """
    Prepare a challenge token for subsequent SSH public key authentication.

    The challenge lifetime is fixed to 10 seconds.

    :param account: Account identifier as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.

    :returns: Challenge token token as a Python struct
              .token string
              .expired_at datetime
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # Cryptographically secure random number.
    # This requires a /dev/urandom like device from the OS
    rng = random.SystemRandom()
    crypto_rand = rng.randint(0, sys.maxsize)

    # give the client 10 seconds max to sign the challenge token
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
    expiration_unix = expiration.strftime("%s")

    challenge_token = 'challenge-%(crypto_rand)s-%(account)s-%(expiration_unix)s' % locals()

    new_challenge_token = models.Token(account=account, token=challenge_token, ip=ip,
                                       expired_at=expiration)
    new_challenge_token.save(session=session)
    session.expunge(new_challenge_token)

    return new_challenge_token


@transactional_session
def delete_expired_tokens(total_workers, worker_number, limit=100, session=None):
    """
    Delete expired tokens.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of tokens to delete.
    :param session:            Database session in use.

    :returns: number of deleted rows
    """

    # get expired tokens
    try:
        # delete all expired tokens except tokens which have refresh token that is still valid
        query = session.query(models.Token.token).filter(and_(models.Token.expired_at < datetime.datetime.utcnow()))\
                                                 .filter(or_(models.Token.refresh_expired_at.is_(None),
                                                             models.Token.refresh_expired_at < datetime.datetime.utcnow()))\
                                                 .with_for_update(skip_locked=True)\
                                                 .order_by(models.Token.expired_at)

        query = partition_load(query, 'state', total_workers, worker_number, session=session)

        # limiting the number of tokens deleted at once
        filtered_tokens = query.limit(limit).subquery()
        # remove expired tokens
        delete_tokens_query = session.query(models.Token.token).filter(models.Token.token.in_(filtered_tokens)).delete(synchronize_session='fetch')

    except Exception as error:
        raise RucioException(error.args)

    return delete_tokens_query


@transactional_session
def delete_expired_oauthreqests(total_workers, worker_number, limit=100, session=None):
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
        query = session.query(models.OAuthRequest.state).filter(models.OAuthRequest.expired_at < datetime.datetime.utcnow())\
                       .with_for_update(skip_locked=True)\
                       .order_by(models.OAuthRequest.expired_at)

        query = partition_load(query, 'state', total_workers, worker_number, session=session)

        # limiting the number of tokens deleted at once
        filtered_oauthparams = query.limit(limit).subquery()
        # remove expired tokens
        delete_oauthparms = session.query(models.OAuthRequest.state).filter(models.OAuthRequest.state.in_(filtered_oauthparams)).delete(synchronize_session='fetch')

    except Exception as error:
        raise RucioException(error.args)

    return delete_oauthparms


# TO-DO this function needs testing !
@transactional_session
def change_refresh_state(token, refresh=False, session=None):
    """
    Changes token refresh state to True/False.

    :param token:      the access token for which the refresh value should be changed.

    :returns: True if all went OK, False is the token is not valid, and an exception otherwise.
    """
    # check if token has a valid refresh token and has not been set to true already
    valid_refresh_token = session.query(models.Token.refresh_token)\
                                 .filter(and_(models.Token.token == token,
                                              models.Token.refresh == false(),
                                              models.Token.refresh_expired_at > datetime.datetime.utcnow())).first()
    if valid_refresh_token:
        try:
            if refresh:
                # update refresh column for a token to True
                session.query(models.Token).filter(models.Token.token == token)\
                                           .update({models.Token.refresh: True})
                session.commit()
            else:
                session.query(models.Token).filter(models.Token.token == token)\
                                           .update({models.Token.refresh: False})
                session.commit()
            return True
        except Exception as error:
            raise RucioException(error.args)
    else:
        return False


@read_session
def get_tokens_for_refresh(total_workers, worker_number, refreshrate=3600, limit=100, session=None):
    """
    Get tokens which expired or will expire before (now + refreshrate)
    next run of this function and which have valid refresh token.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of tokens to refresh per call.
    :param session:            Database session in use.

    :return: filtered_tokens, list of tokens eligible for refresh. Throws an Exception otherwise.
    """
    try:
        # get tokens for refresh that expire in the next <refreshrate> seconds
        expiration_future = datetime.datetime.utcnow() + datetime.timedelta(seconds=refreshrate)
        query = session.query(models.Token).filter(and_(models.Token.refresh == true(),
                                                        models.Token.refresh_expired_at > datetime.datetime.utcnow(),
                                                        models.Token.expired_at < expiration_future))\
                                           .with_for_update(skip_locked=True)\
                                           .order_by(models.Token.expired_at)
        query = partition_load(query, 'token', total_workers, worker_number, session=session)

        # limiting the number of tokens for refresh
        filtered_tokens = query.limit(limit).all()

    except Exception as error:
        raise RucioException(error.args)

    return filtered_tokens


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
    if not token:
        return None

    # Be gentle with bash variables, there can be whitespace
    token = token.strip()

    # Check if token ca be found in cache region
    value = TOKENREGION.get(token)
    if value is NO_VALUE:  # no cached entry found
        value = query_token(token)
        if value is None:
            # identify JWT access token and validte it (JWT access tokens are not saved in DB)
            if len(token.split(".")) == 3:
                value = validate_jwt(token)
                if value is None:
                    return None
            else:
                return None
        # save token in the cache
        TOKENREGION.set(token, value)
    if value.get('lifetime', datetime.datetime(1970, 1, 1)) < datetime.datetime.utcnow():  # check if expired
        TOKENREGION.delete(token)
        return None
    return value


@read_session
def query_token(token, session=None):
    """
    Validate an authentication token using the database. This method will only be called
    if no entry could be found in the according cache.

    :param token: Authentication token as a variable-length string.
    :param session: The database session in use.

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope> }
              if successful, None otherwise.
    """
    # Query the DB to validate token
    ret = session.query(models.Token.account,
                        models.Token.identity,
                        models.Token.expired_at,
                        models.Token.audience,
                        models.Token.scope).\
        filter(models.Token.token == token,
               models.Token.expired_at > datetime.datetime.utcnow()).\
        all()
    if ret:
        return {'account': ret[0][0],
                'identity': ret[0][1],
                'lifetime': ret[0][2],
                'audience': ret[0][3],
                'authz_scope': ret[0][4]}
    return None


@read_session
def validate_jwt(json_web_token, session=None):
    """
    Verifies signature and validity of a JSON Web Token.
    Gets the issuer public keys from the OIDC_client
    and verifies the validity of the token.

    :param json_web_token: the JWT string to verify

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope> }
              if successful, None otherwise.
    """
    global OIDC_clients
    try:
        # getting issuer from the token payload
        issuer = JWT().unpack(json_web_token).payload()['iss']
        OIDC_client = OIDC_clients[issuer]
        issuer_keys = OIDC_client.keyjar.get_issuer_keys(issuer)
        jsig = JWS()
        claim_dict = jsig.verify_compact(json_web_token, issuer_keys)
        identity_string = oidc_identity_string(claim_dict['sub'], claim_dict['iss'])
        expiry_date = datetime.datetime.utcfromtimestamp(claim_dict['exp'])
        scope = None
        if 'scope' in claim_dict:
            scope = claim_dict['scope']
        audience = claim_dict.get('aud', None)
        # this assumes token has been previously looked up in DB before to be sure that we do not have the right account already in the DB !
        account = get_default_account(identity_string, 'OIDC', True, session=session)
        # account = session.query(models.Token.account).filter(models.Token.identity == identity_string).first()
        value = {'account': account[0],
                 'identity': identity_string,
                 'lifetime': expiry_date,
                 'audience': audience,
                 'authz_scope': scope}
        record_counter(counters='JSONWebToken.valid')
        return value
    except:
        record_counter(counters='JSONWebToken.invalid')
        return None
