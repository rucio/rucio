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
#
# PY3K COMPATIBLE

import base64
import datetime
import hashlib
import random
import sys

import paramiko

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE

from rucio.common.utils import generate_uuid
from rucio.core.account import account_exists
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session


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


@read_session
def exist_identity_account(identity, type, account, session=None):
    """
    Check if an identity is mapped to an account.

    :param identity: The user identity as string.
    :param type: The type of identity as a string, e.g. userpass, x509, gss...
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
