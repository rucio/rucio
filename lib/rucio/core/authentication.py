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
from sqlalchemy.sql.expression import bindparam, text, true

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE

from rucio.common.exception import RucioException, CannotAuthenticate, CannotAuthorize, CannotInitOIDCClient
from rucio.common.utils import generate_uuid, oidc_identity_string, build_url
from rucio.core.account import account_exists
from rucio.core.monitor import record_counter, record_timer
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session

from oic import rndstr
from oic.oic import Client, Grant, Token
from oic.utils import time_util
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oic.message import RegistrationResponse, AuthorizationResponse, AccessTokenResponse
from jwkest.jws import JWS
from jwkest.jwt import JWT

from requests import session as web_session
from requests.status_codes import codes
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error
disable_warnings()

try:
    # Python 2
    from urlparse import urlparse
except ImportError:
    # Python 3
    from urllib.parse import urlparse


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

# private/protected file containing Rucio Client secrets
# this client has to be known and configured consistently only on the side of the Identity Provider (XDC IAM)
IAM_OIDC_client_secret_file = '/opt/rucio/etc/IAM_OIDC_client_secret.json'


def get_rucio_OIDC_client():
    """
    Creates a Rucio OIDC Client instance using already pre-defined static client
    pre-registered with the Identity Provider (XDC IAM)

    :returns: Rucio OIDC Client instance if all went without troubles or raises an exception otherwise.
    """
    # initializing a client_id and client_secret - provided in a secret config file
    try:
        with open(IAM_OIDC_client_secret_file) as client_secret_file:
            client_secret = json.load(client_secret_file)
        issuer = client_secret["issuer"]
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        # general parameter discovery about the Identity Provider via the issuers URL
        client.provider_config(issuer)
    except:
        raise CannotInitOIDCClient(traceback.format_exc())
    try:
        # transforming Rucio OIDC Client specific parameters into a registration form
        client_reg = RegistrationResponse(**client_secret)
        # storing such parameters (client_id, client_secret, etc.) into the client itself
        client.store_registration_info(client_reg)
    except:
        raise CannotInitOIDCClient(traceback.format_exc())
    return client


# Initialising Rucio OIDC Client
OIDC_client = get_rucio_OIDC_client()


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
    Finds the Authentication URL in the Rucio DB and redirects user's browser to this URL.

    :param auth_code: Rucio assigned code to redirect authorization securely to IdP via a browser
    :param session: The database session in use.

    :returns: result of the query (authorization URL first or a token if a user asks with the correct code) if everything goes well, exception otherwise.
    """
    try:
        #redirect_code = urlparse.parse_qs(urlparse.urlparse(s).query)['redirect_code']
        redirect_result = session.query(models.OAuthRequest.redirect_msg).filter_by(redirect_code=auth_code).first()
        print("I AM IN REDIRECT ! ", redirect_result)

        if isinstance(redirect_result, tuple):
            if 'http' not in redirect_result[0] and fetchtoken:
                # in this case the function check if the value is a valid token
                v = validate_auth_token(redirect_result[0])
                if not v:
                    print("returning no token:", None)
                    return None
                else:
                    print("returning token:", redirect_result[0])
                    return redirect_result[0]
            elif 'http' in redirect_result[0] and not fetchtoken:
                #return redirection URL
                print("returning url:", redirect_result[0])
                return redirect_result[0]
            else:
                print("returning nothing:", None)
                return None
        print("returning NOTHING:", None)
        return None
    except:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_auth_OIDC(account, auth_scope, auth_server_name, audience, auto=False, polling=False, ip=None, session=None):
    """
    Assembles the authentication request of the Rucio Client for the Rucio user
    for the user's Identity Provider (XDC IAM)/issuer.
    Returned authorization URL (as a string) can be used by the user to grant
    permissions to Rucio to extract his/her (auth_scope(s)), ID & tokens from the Identity Provider.
    (for more Identity Providers if necessary in the future,
    the 'issuer' should become another input parameter here)

    :param account: Rucio Account identifier as a string.
    :param auth_scope: space separated list of scope names. Scope parameter defines which user's
                       info the user allows to provide to the Rucio Client via his/her Identity Provider
    :param auth_server_name: Name of the Rucio authentication server being used.
    :param audience: audience for which tokens are requested
    :auto: If True, the function will return authentication URL to the Rucio Client
           which will log-in user with his IdP credentials automatically
           If False, the function will return a URL to be used by the user
           in his/her browser in order to authenticate via IdP.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: User & Rucio OIDC Client specific Authorization URL as a string.
    """
    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    try:
        start = time.time()
        # get the redirect URIs (they have to be included in Rucio OIDC Client configuration)
        with open(IAM_OIDC_client_secret_file) as client_secret_file:
            client_secret = json.load(client_secret_file)

        # redirect_url needs to be one of those defined in the Rucio OIDC Client configuration
        redirect_url = None
        # we point the redirect to go later to the same server
        # as the one that defined this autorization for the user
        redirect_urls = [url for url in client_secret["redirect_uris"]
                         if ((auth_server_name in url) and ('auth/OIDC_token') in url)]
        if len(redirect_urls) == 1:
            redirect_url = redirect_urls[0]
        else:
            raise CannotAuthenticate('%s redirect URL(s) found in the defined ' % (len(redirect_urls)) +
                                     'Rucio OIDC Client which corresponds to the current auth server.')
        # user_session_state: random string in order to keep track of
        # responses to outstanding requests (state).
        user_session_state = rndstr(50)
        # user_session_nonce: random string in order to associate
        # a client session with an ID Token and to mitigate replay attacks.
        user_session_nonce = rndstr(50)
        # Assembling the Rucio user related authentication URL (AuthN) to be returned to the user
        auth_args = {"client_id": OIDC_client.client_id,
                     "grant_types": ["authorization_code"],
                     "response_type": "code",
                     "scope": auth_scope,
                     "nonce": user_session_nonce,
                     "audience": audience,
                     "redirect_uri": redirect_url,
                     "state": user_session_state}

        auth_req = OIDC_client.construct_AuthorizationRequest(request_args=auth_args)
        print("CONSTRUCTED REQUEST:", auth_req)
        auth_url = auth_req.request(OIDC_client.authorization_endpoint)
        print("CONSTRUCTED URL:", auth_url)
        redirect_code = None
        if not auto:
            redirect_code = rndstr(23)
            if polling:
                redirect_code+='_polling'
        print("AUTO IS ", auto)
        # 10 min lifetime for the session (maximum to ensure that if token is
        # temporarily placed here it will be removed soon)
        expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=600)
        oauth_session_params = models.OAuthRequest(account=account,
                                                   state=user_session_state,
                                                   nonce=user_session_nonce,
                                                   redirect_code=redirect_code,
                                                   redirect_msg=auth_url,
                                                   expired_at=expired_at,
                                                   ip=ip)
        oauth_session_params.save(session=session)
        session.expunge(oauth_session_params)
        if not auto:
            auth_url = build_url('https://' + auth_server_name, path='auth/OIDC_redirect', params=redirect_code)

        print("RESPONDING WITH", auth_url)
        record_counter(counters='IdP_authentication.request')
        record_timer(stat='IdP_authentication.request', time=time.time() - start)
        return auth_url

    except:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_token_OIDC(auth_query_string, auth_server_name, ip=None, session=None):
    """
    After Rucio User authenticated with the Identity Provider via the authorization URL,
    and by that granted to the Rucio OIDC client an access to her/him information (auth_scope(s)),
    the Identity Provider redirects her/him to /auth/OIDC_Token with authz code
    and session state encoded within the URL. This URL's query string becomes the input parameter
    for this function that eventually gets user's info and tokens from the Identity Provider.

    :param auth_query_string: Identity Provider redirection URL query string
                              containing AuthZ code and user session state parameters.
    :param auth_server_name: Name of the Rucio authentication server being used.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: tuple ("fetchcode", <code>) or ("token", <token>) depending on
    the way authentication was obtained (via browser or if Rucio was trusted with users IdP credentials)
    """
    try:
        traceback.format_exc()
        start = time.time()
        # parsing the authorization query string by the Rucio OIDC Client
        authz_code_response = OIDC_client.parse_response(AuthorizationResponse,
                                                         info=auth_query_string,
                                                         sformat="urlencoded")
        code = authz_code_response["code"]
        user_session_state = authz_code_response["state"]

        # check continuity of the requests
        result = session.query(models.OAuthRequest).filter_by(state=user_session_state).first()

        if result is None:
            raise CannotAuthenticate("User related Rucio OIDC session could not" +
                                     "keep track of responses from outstanding requests.")

        account = result.account
        nonce = result.nonce
        redirect_code = result.redirect_code

        record_counter(counters='IdP_authentication.code_granted')

        # assembling requests for an access token
        with open(IAM_OIDC_client_secret_file) as client_secret_file:
            client_secret = json.load(client_secret_file)

        # redirect_url needs to be one of those defined
        # in the Rucio OIDC Client configuration
        redirect_url = None
        # we point the redirect to go later to the same
        # server as the one that started the auth process
        redirect_urls = [url for url in client_secret["redirect_uris"]
                         if ((auth_server_name in url) and ('auth/OIDC_token') in url)]
        if len(redirect_urls) == 1:
            redirect_url = redirect_urls[0]
        else:
            raise CannotAuthenticate('%s redirect URL(s) found in the defined ' % (len(redirect_urls)) +
                                     'Rucio OIDC Client which corresponds to the current auth server.')
        # assembling parameters to request an access token
        args = {"code": code,
                "redirect_uri": redirect_url}
        # exchange access code for a access token
        oidc_tokens = OIDC_client.do_access_token_request(state=user_session_state,
                                                          request_args=args,
                                                          authn_method="client_secret_basic")
        # we can request more information, e.g. getting user info ca be done with
        # userinfo = OIDC_client.do_user_info_request(state=user_session_state)

        # mitigate replay attacks
        ID_token_nonce = oidc_tokens['id_token']['nonce']
        if ID_token_nonce != nonce:
            raise CannotAuthenticate("ID token could not be associated with the Rucio OIDC Client session." +
                                     " This points to possible replay attack !")

        identity_string = oidc_identity_string(oidc_tokens['id_token']['sub'], oidc_tokens['id_token']['iss'])

        # check if given account has the identity registered
        if not exist_identity_account(identity_string, IdentityType.OIDC, account):
            raise CannotAuthenticate("OIDC identity '%s' of the '%s' account is unknown to Rucio." % (identity_string, account))

        record_counter(counters='IdP_authentication.success')
        # get access token expiry timestamp
        expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=oidc_tokens['expires_in'])
        audience = None
        if 'audience' in oidc_tokens:
            audience = oidc_tokens['audience']
        # In case user requested to grant Rucio an refresh token, this token will get saved in the DB
        if 'refresh_token' in oidc_tokens:

            # create new refresh token

            try:
                exp = json.loads(JWT().unpack(oidc_tokens['refresh_token']).part[1])['exp']
                refresh_expired_at = datetime.datetime.utcfromtimestamp(exp)
            except:
                # 4 day expiry period by default
                refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(hours=96)

            new_token = models.Token(account=account,
                                     token=oidc_tokens['access_token'],
                                     refresh_token=oidc_tokens['refresh_token'],
                                     scope=oidc_tokens['scope'],
                                     refresh=False,
                                     audience=audience,
                                     expired_at=expired_at,
                                     refresh_expired_at=refresh_expired_at,
                                     identity=identity_string,
                                     ip=ip)
            new_token.save(session=session)
            session.expunge(new_token)
            record_counter(counters='IdP_authorization.access_token.saved')
            record_counter(counters='IdP_authorization.refresh_token.saved')
            # remove refresh token info (not for the user)
            new_token.refresh_token = None
            new_token.refresh_expired_at = None

        else:
            # return an access token
            new_token = models.Token(account=account,
                                     token=oidc_tokens['access_token'],
                                     scope=oidc_tokens['scope'],
                                     refresh=False,
                                     expired_at=expired_at,
                                     audience=audience,
                                     identity=identity_string,
                                     ip=ip)
            new_token.save(session=session)
            session.expunge(new_token)
            record_counter(counters='IdP_authorization.access_token.saved')
        # in case authentication via browser was requested, we save the token under a fetchcode
        # so that the Rucio Client can temporarily get it from the oauth_requests table
        if redirect_code:
            # temporarily save token also in the OAuth Request table
            if '_polling' not in redirect_code:
                fetchcode = rndstr(50)
                session.query(models.OAuthRequest).filter(models.OAuthRequest.state == user_session_state)\
                       .update({models.OAuthRequest.redirect_code: fetchcode,
                                models.OAuthRequest.redirect_msg: new_token.token})
            else:
                session.query(models.OAuthRequest).filter(models.OAuthRequest.state == user_session_state)\
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
        record_counter(counters='IdP_authorization.access_token.exception')
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def refresh_token_OIDC(token_object, maxperiod=96, session=None):
    """
    Requests new access and refresh tokens from the Identity Provider.
    Assumption: The Identity Provider issues refresh tokens for one time use only and
    with a limited lifetime. The refresh tokens are invalidated no matter which of these
    situations happens first.

    :param token_object: Rucio models.Token DB row object
    :param maxperiod:  maximum allowed period during which a token can be refreshed repetitively

    :returns: Access Token as a Python struct
              .token string
              .expired_at datetime
    """

    try:
        start = time.time()
        refresh_start = datetime.datetime.utcnow()
        record_counter(counters='IdP_authorization.refresh_token.request')
        if hasattr(token_object, 'refresh_start'):
            if token_object.refresh_start:
                refresh_start = token_object.refresh_start

        if (datetime.datetime.utcnow() - refresh_start > datetime.timedelta(hours=maxperiod)):
            # abort refresh attempts
            session.query(models.Token).filter(models.Token.token == token_object.token).update({models.Token.refresh: False})
            session.commit()
            raise CannotAuthorize("Rucio aborted refresh token attempts due to exceeding max refresh limit of %i hours." % maxperiod)

        # checking the expiry date of the refresh token
        if (token_object.refresh_expired_at is None) or (not token_object.refresh_expired_at > datetime.datetime.utcnow()):
            raise CannotAuthorize("Rucio aborted refresh token attempts due to an attempt to use expired refresh token.")

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
        audience = None
        if 'audience' in oidc_tokens:
            audience = oidc_tokens['audience']
        if 'refresh_token' in oidc_tokens and 'access_token' in oidc_tokens:
            # aborting refresh of the original token (keeping it in place until it expires) and setting the expiry time of the refresh token to now
            session.query(models.Token).filter(models.Token.token == token_object.token)\
                   .update({"refresh": False, "refresh_expired_at": datetime.datetime.utcnow()})
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
                                     scope=oidc_tokens['scope'],
                                     audience=audience,
                                     refresh=True,
                                     expired_at=expired_at,
                                     refresh_expired_at=refresh_expired_at,
                                     refresh_start=refresh_start,
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

        if worker_number and total_workers and total_workers - 1 > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('worker_number', worker_number - 1), bindparam('total_workers', total_workers - 1)]
                query = query.filter(text('ORA_HASH(token, :total_workers) = :worker_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter(text('mod(md5(token), %s) = %s' % (total_workers - 1, worker_number - 1)))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter(text('mod(abs((\'x\'||md5(token))::bit(32)::int), %s) = %s' % (total_workers - 1, worker_number - 1)))
        # limiting the number of tokens deleted at once
        filtered_tokens = query.limit(limit).subquery()
        # remove expired tokens
        delete_tokens_query = session.query(models.Token.token).filter(models.Token.token.in_(filtered_tokens)).delete(synchronize_session='fetch')

    except Exception as error:
        print(traceback.format_exc())
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
        if worker_number and total_workers and total_workers - 1 > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('worker_number', worker_number - 1), bindparam('total_workers', total_workers - 1)]
                query = query.filter(text('ORA_HASH(state, :total_workers) = :worker_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter(text('mod(md5(state), %s) = %s' % (total_workers - 1, worker_number - 1)))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter(text('mod(abs((\'x\'||md5(state))::bit(32)::int), %s) = %s' % (total_workers - 1, worker_number - 1)))
        # limiting the number of tokens deleted at once
        filtered_oauthparams = query.limit(limit).subquery()
        # remove expired tokens
        delete_oauthparms = session.query(models.OAuthRequest.state).filter(models.OAuthRequest.state.in_(filtered_oauthparams)).delete(synchronize_session='fetch')

    except Exception as error:
        print(traceback.format_exc())
        raise RucioException(error.args)

    return delete_oauthparms


@read_session
def get_tokens_for_refresh(total_workers, worker_number, refreshrate=3600, limit=100, session=None):
    """
    Get tokens which expired or will expire before (now + refreshrate)
    next run of this function and which have valid refresh token.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of tokens to refresh per call.
    :param session:            Database session in use.

    :return: filtered_tokens, list of tokens eligible for refresh
    """
    try:
        # get tokens for refresh that expire in the next <refreshrate> seconds
        expiration_future = datetime.datetime.utcnow() + datetime.timedelta(seconds=refreshrate)
        query = session.query(models.Token).filter(and_(models.Token.refresh == true(),
                                                        models.Token.refresh_expired_at > datetime.datetime.utcnow(),
                                                        models.Token.expired_at < expiration_future))\
                                           .with_for_update(skip_locked=True)\
                                           .order_by(models.Token.expired_at)
        if worker_number and total_workers and total_workers - 1 > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('worker_number', worker_number - 1), bindparam('total_workers', total_workers - 1)]
                query = query.filter(text('ORA_HASH(token, :total_workers) = :worker_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter(text('mod(md5(token), %s) = %s' % (total_workers - 1, worker_number - 1)))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter(text('mod(abs((\'x\'||md5(token))::bit(32)::int), %s) = %s' % (total_workers - 1, worker_number - 1)))

        # limiting the number of tokens for refresh
        filtered_tokens = query.limit(limit).all()

    except Exception as error:
        print(traceback.format_exc())
        raise RucioException(error.args)

    return filtered_tokens


def validate_auth_token(token):
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.
    :param session: The database session in use.

    :returns: dictionary { account: <account name>, identity: <identity>, lifetime: <token lifetime> }
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

    :returns: dictionary { account: <account name>, identity: <identity>, lifetime: <token lifetime> }
              if successful, None otherwise.
    """
    # Query the DB to validate token
    ret = session.query(models.Token.account,
                        models.Token.identity,
                        models.Token.expired_at).\
        filter(models.Token.token == token,
               models.Token.expired_at > datetime.datetime.utcnow()).\
        all()
    if ret:
        return {'account': ret[0][0],
                'identity': ret[0][1],
                'lifetime': ret[0][2]}
    return None


@read_session
def validate_jwt(json_web_token, session=None):
    """
    Verifies signature and validity of a JSON Web Token.
    Gets the issuer public keys from the OIDC_client
    and verifies the validity of the token.

    :param json_web_token: the JWT string to verify

    :returns: dictionary { account: <account name>, identity: <identity>, lifetime: <token lifetime> }
              if successful, None otherwise.
    """
    try:
        issuer_keys = OIDC_client.keyjar.get_issuer_keys(OIDC_client.provider_info["issuer"])
        jsig = JWS()
        claim_dict = jsig.verify_compact(json_web_token, issuer_keys)
        identity_string = oidc_identity_string(claim_dict['sub'], claim_dict['iss'])
        expiry_date = datetime.datetime.utcfromtimestamp(claim_dict['exp'])
        # get token account info, assuming each Rucio account has maximum 1 OIDC identity
        account = session.query(models.Token.account).filter(models.Token.identity == identity_string).first()
        value = {'account': account[0],
                 'identity': identity_string,
                 'lifetime': expiry_date}
        record_counter(counters='JSONWebToken.valid')
        return value
    except:
        record_counter(counters='JSONWebToken.invalid')
        return None
