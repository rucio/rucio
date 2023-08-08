# -*- coding: utf-8 -*-
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

import datetime
import hashlib
import random
import re
import sys
import traceback
from base64 import b64decode
from typing import TYPE_CHECKING

import paramiko
from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE
from sqlalchemy import delete, null, or_, select

from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get_bool
from rucio.common.exception import CannotAuthenticate, RucioException
from rucio.common.utils import chunks, generate_uuid, date_to_str
from rucio.core.account import account_exists
from rucio.core.oidc import validate_jwt
from rucio.db.sqla import filter_thread_work
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from typing import Any, Union


def strip_x509_proxy_attributes(dn: str) -> str:
    """Strip X509 proxy attributes from a DN.

    When an X509 VOMS proxy certificate is produced, an additional Common Name
    attribute is added to the subject of the original certificate.  Its value
    can take different forms.  For proxy versions 3 and later (the default), the
    value is a numeric.  For previous versions, the value is exclusively one of
    'limited proxy' or 'proxy', depending on how it was produced (the most
    trustworthy documentation on this seems to be the VOMS source code itself;
    refer to the file sslutils.c).  Note that this addition might happen more
    than once (e.g. if a limited proxy is used to produce a full proxy).

    By default, the Apache server will return the DN in an RFC-compliant format,
    which can look like this:
        CN=John Doe,OU=Users,DC=example,DC=com
    However, in case the LegacyDNStringFormat of mod_ssl is enabled, then it can
    look like this instead:
        /DC=com/DC=example/OU=Users/CN=John Doe
    In the first case, the Common Name attributes added by VOMS are prepended,
    whereas in the second case, they are appended.

    The motivation for stripping these attributes is to avoid having to store
    multiple DNs in the database (as different identities).
    """
    if dn.startswith('/'):
        regexp = r'(/CN=(limited proxy|proxy|[0-9]+))+$'
    else:
        regexp = r'^(CN=(limited proxy|proxy|[0-9]+),)+'

    return re.sub(regexp, '', dn)


def token_key_generator(namespace, fni, **kwargs):
    """ :returns: generate key function """
    def generate_key(token, *, session: "Session"):
        """ :returns: token """
        return token
    return generate_key


if config_get_bool('cache', 'use_external_cache_for_auth_tokens', default=False):
    TOKENREGION = make_region_memcached(expiration_time=900, function_key_generator=token_key_generator)
else:
    TOKENREGION = make_region(function_key_generator=token_key_generator).configure('dogpile.cache.memory', expiration_time=900)


@transactional_session
def get_auth_token_user_pass(account, username, password, appid, ip=None, *, session: "Session"):
    """
    Authenticate a Rucio account temporarily via username and password.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client a a string.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    query = select(
        models.Identity
    ).where(
        models.Identity.identity == username,
        models.Identity.identity_type == IdentityType.USERPASS
    )
    result = session.execute(query).scalar()

    db_salt = result['salt']
    db_password = result['password']

    salted_password = db_salt + password.encode()
    if db_password != hashlib.sha256(salted_password).hexdigest():
        return None

    # get account identifier
    query = select(
        models.IdentityAccountAssociation
    ).where(
        models.IdentityAccountAssociation.identity == username,
        models.IdentityAccountAssociation.identity_type == IdentityType.USERPASS,
        models.IdentityAccountAssociation.account == account
    )
    result = session.execute(query).scalar()

    db_account = result['account']

    # remove expired tokens
    __delete_expired_tokens_account(account=account, session=session)

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = f'{account}-{username}-{appid}-{tuid}'
    new_token = models.Token(account=db_account, identity=username, token=token, ip=ip)
    new_token.save(session=session)

    return token_dictionary(new_token)


@transactional_session
def get_auth_token_x509(account, dn, appid, ip=None, *, session: "Session"):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param id: The application identifier as a string.
    :param ipaddr: IP address of the client as a string.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # remove expired tokens
    __delete_expired_tokens_account(account=account, session=session)

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = f'{account}-{dn}-{appid}-{tuid}'
    new_token = models.Token(account=account, identity=dn, token=token, ip=ip)
    new_token.save(session=session)

    return token_dictionary(new_token)


@transactional_session
def get_auth_token_gss(account, gsstoken, appid, ip=None, *, session: "Session"):
    """
    Authenticate a Rucio account temporarily via a GSS token.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param gsscred: GSS principal@REALM as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # remove expired tokens
    __delete_expired_tokens_account(account=account, session=session)

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = f'{account}-{gsstoken}-{appid}-{tuid}'
    new_token = models.Token(account=account, token=token, ip=ip)
    new_token.save(session=session)

    return token_dictionary(new_token)


@transactional_session
def get_auth_token_ssh(account, signature, appid, ip=None, *, session: "Session"):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param signature: Response to server challenge signed with SSH private key as string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """
    if not isinstance(signature, bytes):
        signature = signature.encode()

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # get all active challenge tokens for the requested account
    query = select(
        models.Token
    ).where(
        models.Token.expired_at >= datetime.datetime.utcnow(),
        models.Token.account == account,
        models.Token.token.like('challenge-%')
    )
    active_challenge_tokens = session.execute(query).scalars().all()

    # get all identities for the requested account
    query = select(
        models.IdentityAccountAssociation
    ).where(
        models.IdentityAccountAssociation.identity_type == IdentityType.SSH,
        models.IdentityAccountAssociation.account == account
    )
    identities = session.execute(query).scalars().all()

    # no challenge tokens found
    if not active_challenge_tokens:
        return None

    # try all available SSH identities for the account with the provided signature
    match = False
    for identity in identities:
        data = identity['identity'].split()[1]
        data += '=' * ((4 - len(data) % 4) % 4)  # adding required padding
        pub_k = paramiko.RSAKey(data=b64decode(data))
        for challenge_token in active_challenge_tokens:
            if pub_k.verify_ssh_sig(str(challenge_token['token']).encode(),
                                    paramiko.Message(signature)):
                match = True
                break
        if match:
            break

    if not match:
        return None

    # remove expired tokens
    __delete_expired_tokens_account(account=account, session=session)

    # create new rucio-auth-token for account
    tuid = generate_uuid()  # NOQA
    token = f'{account}-ssh:pubkey-{appid}-{tuid}'
    new_token = models.Token(account=account, token=token, ip=ip)
    new_token.save(session=session)

    return token_dictionary(new_token)


@transactional_session
def get_ssh_challenge_token(account, appid, ip=None, *, session: "Session"):
    """
    Prepare a challenge token for subsequent SSH public key authentication.

    The challenge lifetime is fixed to 10 seconds.

    :param account: Account identifier as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.

    :returns: A dict with token and expires_at entries.
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

    challenge_token = f'challenge-{crypto_rand}-{account}-{expiration_unix}'

    new_challenge_token = models.Token(account=account, token=challenge_token, ip=ip,
                                       expired_at=expiration)
    new_challenge_token.save(session=session)

    return token_dictionary(new_challenge_token)


@transactional_session
def get_auth_token_saml(account, saml_nameid, appid, ip=None, *, session: "Session"):
    """
    Authenticate a Rucio account temporarily via SAML.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param saml_nameid: SAML NameID of the client.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client a a string.
    :param session: The database session in use.

    :returns: A dict with token and expires_at entries.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    # remove expired tokens
    __delete_expired_tokens_account(account=account, session=session)

    tuid = generate_uuid()  # NOQA
    token = f'{account}-{saml_nameid}-{appid}-{tuid}'
    new_token = models.Token(account=account, identity=saml_nameid, token=token, ip=ip)
    new_token.save(session=session)

    return token_dictionary(new_token)


@transactional_session
def redirect_auth_oidc(auth_code, fetchtoken=False, *, session: "Session"):
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
        query = select(
            models.OAuthRequest.redirect_msg
        ).where(
            models.OAuthRequest.access_msg == auth_code
        )
        redirect_result = session.execute(query).scalar()

        if not redirect_result:
            return None

        if 'http' not in redirect_result and fetchtoken:
            # in this case the function check if the value is a valid token
            vdict = validate_auth_token(redirect_result, session=session)
            if vdict:
                return redirect_result
            return None
        elif 'http' in redirect_result and not fetchtoken:
            # return redirection URL
            return redirect_result
    except:
        raise CannotAuthenticate(traceback.format_exc())


@transactional_session
def delete_expired_tokens(total_workers, worker_number, limit=1000, *, session: "Session"):
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
        query = select(
            models.Token.token
        ).where(
            models.Token.expired_at <= datetime.datetime.utcnow(),
            or_(
                models.Token.refresh_expired_at == null(),
                models.Token.refresh_expired_at <= datetime.datetime.utcnow()
            )
        ).order_by(
            models.Token.expired_at
        )

        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='token')

        # limiting the number of tokens deleted at once
        query = query.limit(limit)
        # Oracle does not support chaining order_by(), limit(), and
        # with_for_update(). Use a nested query to overcome this.
        if session.bind.dialect.name == 'oracle':
            query = select(
                models.Token.token
            ).where(
                models.Token.token.in_(query)
            ).with_for_update(
                skip_locked=True
            )
        else:
            query = query.with_for_update(skip_locked=True)
        # remove expired tokens
        deleted_tokens = 0
        for tokens in session.execute(query).scalars().partitions(10):
            query = delete(
                models.Token
            ).where(
                models.Token.token.in_(tokens)
            )
            deleted_tokens += session.execute(query).rowcount

    except Exception as error:
        raise RucioException(error.args)

    return deleted_tokens


@read_session
def query_token(token, *, session: "Session"):
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
    query = select(
        models.Token.account,
        models.Token.identity,
        models.Token.expired_at.label('lifetime'),
        models.Token.audience,
        models.Token.oidc_scope.label('authz_scope')
    ).where(
        models.Token.token == token,
        models.Token.expired_at > datetime.datetime.utcnow()
    )
    result = session.execute(query).first()
    if result:
        return result._asdict()
    return None


@transactional_session
def validate_auth_token(token: str, *, session: "Session") -> "dict[str, Any]":
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.

    :returns: dictionary { account: <account name>,
                           identity: <identity>,
                           lifetime: <token lifetime>,
                           audience: <audience>,
                           authz_scope: <authz_scope> }
              if successful
    :raises: CannotAuthenticate if unsuccessful
    """
    if not token:
        raise CannotAuthenticate("No token was passed!")

    # Be gentle with bash variables, there can be whitespace
    token = token.strip()
    cache_key = token.replace(' ', '')

    # Check if token ca be found in cache region
    value: "Union[NO_VALUE, dict[str, Any]]" = TOKENREGION.get(cache_key)
    if value is NO_VALUE:  # no cached entry found
        value = query_token(token, session=session)
        if not value:
            # identify JWT access token and validte
            # & save it in Rucio if scope and audience are correct
            if len(token.split(".")) == 3:
                value = validate_jwt(token, session=session)
            else:
                raise CannotAuthenticate(traceback.format_exc())
        # save token in the cache
        TOKENREGION.set(cache_key, value)
    lifetime = value.get('lifetime', datetime.datetime(1970, 1, 1))
    if lifetime < datetime.datetime.utcnow():  # check if expired
        TOKENREGION.delete(cache_key)
        raise CannotAuthenticate(f"Token found but expired since {date_to_str(lifetime)}.")
    return value


def token_dictionary(token: models.Token):
    return {'token': token.token, 'expires_at': token.expired_at}


@transactional_session
def __delete_expired_tokens_account(account, *, session: "Session"):
    """"
    Deletes expired tokens from the database.

    :param account: Account to delete expired tokens.
    :param session: The database session in use.
    """
    select_query = select(
        models.Token.token
    ).where(
        models.Token.expired_at < datetime.datetime.utcnow(),
        models.Token.account == account
    ).with_for_update(
        skip_locked=True
    )
    tokens = session.execute(select_query).scalars().all()

    for chunk in chunks(tokens, 100):
        delete_query = delete(
            models.Token
        ).prefix_with(
            "/*+ INDEX(TOKENS_ACCOUNT_EXPIRED_AT_IDX) */"
        ).where(
            models.Token.token.in_(chunk)
        )
        session.execute(delete_query)
