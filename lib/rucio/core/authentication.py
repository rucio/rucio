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
# - Martin Barisits <martin.barisits@cern.ch>, 2012-2017
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

import paramiko

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE

from rucio.common.exception import CannotAuthenticate
from rucio.common.utils import generate_uuid
from rucio.core.account import account_exists
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session

from oic import rndstr
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oic.message import RegistrationResponse
from oic.oic.message import AuthorizationResponse


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


OIDCREGION = make_region(
    function_key_generator=token_key_generator
).configure(
    'dogpile.cache.memcached',
    expiration_time=3600,
    arguments={'url': "127.0.0.1:11211", 'distributed_lock': True}
)


def get_rucio_OIDC_client():
    """
    Creates a Rucio OIDC Client instance, using already pre-defined static client
    pre-registered with the Identity Provider (XDC IAM)

    :returns: Rucio OIDC Client instance if all went without troubles and raises an exception otherwise.
    """
    # initializing a client_id and client_secret - provided in a secret config file
    with open('/opt/rucio/etc/IAM_OIDC_client_secret.json') as client_secret_file:
            client_secret = json.load(client_secret_file)
    issuer = client_secret["issuer"]
    try:
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        # general parameter discovery about the Identity Provider via the issuers URL
        client.provider_config(issuer)
    except:
        raise CannotAuthenticate(traceback.format_exc())

    try:
        # transforming Rucio OIDC Client specific parameters into a registration form
        client_reg = RegistrationResponse(**client_secret)
        # storing such parameters (client_id, client_secret, etc.) into the client itself
        client.store_registration_info(client_reg)
    except:
        raise CannotAuthenticate(traceback.format_exc())
    return client


OIDC_Client = get_rucio_OIDC_client()


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
                                       models.Token.account == account).delete()

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = '%(account)s-%(username)s-%(appid)s-%(tuid)s' % locals()
    new_token = models.Token(account=db_account, token=token, ip=ip)
    new_token.save(session=session)
    session.expunge(new_token)

    return new_token


@transactional_session
def get_auth_OIDC(account, auth_server_name, session=None):
    """
    Authenticates Rucio user with the user's Identity Provider (e.g. XDC IAM) - issuer -
    and returns an authorization URL (as a string) with which the user can grant
    permissions to Rucio to extract his/her ID & tokens from the Identity Provider.
    (for more Identity Providers if necessary in the future,
    the 'issuer' should become another input parameter here)

    :param account: Rucio Account identifier as a string.
    :param auth_server_name: Name of the Rucio authentication server being used.

    :returns: User & Rucio OIDC Client specific Authorization URL as a string.
    """
    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    try:
        # TO-BE-IMPLEMENTED check if there is a refresh token, in that case request an access token and save it
        # without the need for user authentication with Identity Provider

        ''' Implementing work with refresh tokens
        # assembling request argument dictionary
        args = {"code": code,
                "redirect_uri": redirect_url,
                "grant_type": refresh_token,
                "refresh_token": oidc_tokens['refresh_token']}
        resp = OIDC_Client.do_access_token_request(state=user_session_state, scope=scope, request_args=args, authn_method="client_secret_basic")
        '''

        # get the redirect URIs (they have to be included in Rucio OIDC Client configuration)
        with open('/opt/rucio/etc/IAM_OIDC_client_secret.json') as client_secret_file:
            client_secret = json.load(client_secret_file)

        # scope parameter defines info that we are allowed to request about the user at the Identity Provider
        scope = client_secret["scope"]
        # redirect_url needs to be one of those defined by in the Rucio OIDC Client configuration
        redirect_url = None
        # we point the redirect to go later to the same server as the one that started the auth process
        redirect_urls = [url for url in client_secret["redirect_uris"] if ((auth_server_name in url) and ('auth/OIDC_token') in url)]
        if len(redirect_urls) == 1:
            redirect_url = redirect_urls[0]

        # user_session_state: random string in order to keep track of responses to outstanding requests (state).
        user_session_state = rndstr()
        # user_session_nonce: random string in order to associate a client session with an ID Token and to mitigate replay attacks.
        user_session_nonce = rndstr()
        user_tuple = (account, user_session_nonce)
        # keeping these tracking parameters in the memcached
        OIDCREGION.set(user_session_state, user_tuple)

        # Assembling the Rucio user related authentication URL (AuthN) to be returned to the user
        auth_args = {"client_id": OIDC_Client.client_id,
                     "grant_types": ["authorization_code"],
                     "response_type": "code",
                     "scope": scope,
                     "nonce": user_session_nonce,
                     "redirect_uri": redirect_url,
                     "state": user_session_state}

        auth_req = OIDC_Client.construct_AuthorizationRequest(request_args=auth_args)
        auth_url = auth_req.request(OIDC_Client.authorization_endpoint)

        return auth_url

    except:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def get_token_OIDC(auth_query_string, auth_server_name, session=None):
    """
    After Rucio User authenticated witht he Identity Provider via a authorisation URL,
    and eventually granted to the Rucio OIDC client an access to his information,
    the Identity Provider redirects her/him to /auth/OIDC_Token with authz code
    and session state encoded within the URL. This URL's query string becomes the input parameter
    for this function that eventually gets user's info and tokens from the Identity Provider.

    :param auth_query_string: Identity Provider redirection URL query string
                            containing AuthZ code and user session state parameters.

    :returns: Access token as a Python struct .token string .expired_at datetime .identity string
    """
    try:
        # parsing the authorization query string by the Rucio OIDC Client
        authz_code_response = OIDC_Client.parse_response(AuthorizationResponse, info=auth_query_string, sformat="urlencoded")
        code = authz_code_response["code"]
        user_session_state = authz_code_response["state"]

        # check continuity of the requests
        user_session_tuple = OIDCREGION.get(user_session_state)
        if OIDCREGION.get(user_session_state) is NO_VALUE:
            raise CannotAuthenticate("User related Rucio OIDC session could not keep track of responses from outstanding requests.")

        account = user_session_tuple[0]
        nonce = user_session_tuple[1]
        OIDCREGION.delete(user_session_state)

        # assembling requests for an access token
        with open('/opt/rucio/etc/IAM_OIDC_client_secret.json') as client_secret_file:
            client_secret = json.load(client_secret_file)

        # redirect_url needs to be one of those defined by in the Rucio OIDC Client configuration
        redirect_url = None
        # we point the redirect to go later to the same server as the one that started the auth process
        redirect_urls = [url for url in client_secret["redirect_uris"] if ((auth_server_name in url) and ('auth/OIDC_token') in url)]
        if len(redirect_urls) == 1:
            redirect_url = redirect_urls[0]
        # Note: refresh token is being returned as well as Rucio OIDC Client scope config includes 'offline_access'
        scope = client_secret["scope"]
        # assembling request argument dictionary
        args = {"code": code,
                "redirect_uri": redirect_url}
        # exchange access code for a access token
        oidc_tokens = OIDC_Client.do_access_token_request(state=user_session_state, scope=scope, request_args=args, authn_method="client_secret_basic")
        # we can request more information, e.g. getting user info ca be done with
        # userinfo = OIDC_Client.do_user_info_request(state=user_session_state)

        # mitigate replay attacks
        ID_token_nonce = oidc_tokens['id_token']['nonce']
        if ID_token_nonce != nonce:
            raise CannotAuthenticate("ID token could not be associated with the Rucio OIDC Client session. This points to possible replay attack !")

        identity_string = 'SUB=' + oidc_tokens['id_token']['sub'] + ', ISS=' + oidc_tokens['id_token']['iss']

        # get account identifier
        result = session.query(models.IdentityAccountAssociation).filter_by(identity=identity_string,
                                                                            identity_type=IdentityType.OIDC,
                                                                            account=account).first()
        db_account = result['account']
        ''' remove all expired tokens (including access and refresh tokens)
            if refresh tokens are given a lifetime, we need to distinguish their deletion
            we need to send POST request to oauth/revoke endpoint to invalidate them on the side of the Identity Provider
        '''

        session.query(models.Token).filter(models.Token.expired_at < datetime.datetime.utcnow(),
                                           models.Token.account == account).delete()

        # access_token expiry date
        expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=oidc_tokens['expires_in'])
        # create new rucio-auth-token for account
        new_token = models.Token(account=db_account, token=oidc_tokens['access_token'], expired_at=expired_at, identity=identity_string)

        ''' refresh tokens (from XDC IAM) never expire (as of Jun 2019)
            (if we make them expire in the DB, we need to introduce a separate deletion mechanism)
            expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=2419200)
            OR
            expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=3153600000)
            new_token = models.Token(account=db_account, token=oidc_tokens['refresh_token'], expired_at=expired_at  , ip=ip)
        '''
        new_token.save(session=session)
        session.expunge(new_token)
        return new_token

    except:
        raise CannotAuthenticate(traceback.format_exc())


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
                                       models.Token.account == account).delete()

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
                                       models.Token.account == account).delete()

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
                                       models.Token.account == account).delete()

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


def validate_auth_token(token):
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.
    :param session: The database session in use.

    :returns: Tuple(account identifier, token lifetime) if successful, None otherwise.
    """
    if not token:
        return

    # Be gentle with bash variables, there can be whitespace
    token = token.strip()

    # Check if token ca be found in cache region
    value = TOKENREGION.get(token)
    if value is NO_VALUE:  # no cached entry found
        value = query_token(token)
        value and TOKENREGION.set(token, value)
    elif value.get('lifetime', datetime.datetime(1970, 1, 1)) < datetime.datetime.utcnow():  # check if expired
        TOKENREGION.delete(token)
        return
    return value


@read_session
def query_token(token, session=None):
    """
    Validate an authentication token using the database. This method will only be called
    if no entry could be found in the according cache.

    :param token: Authentication token as a variable-length string.
    :param session: The database session in use.

    :returns: Tuple(account identifier, token lifetime) if successful, None otherwise.
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
