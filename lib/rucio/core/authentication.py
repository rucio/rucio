# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

import datetime
import hashlib
import uuid

from rucio.core.account import account_exists
from rucio.db import models
from rucio.db.session import read_session, transactional_session


@read_session
def exist_identity_account(identity, type, account, session=None):
    """ Check if a identity is mapped to an account.

    :param identity: The user identity.
    :param type: The type of identity, e.g. userpass, x509, gss...
    :param account: The account name.
    :param session: The database session in use.

    :returns: True if identity is mapped to account, otherwise False

    """
    query = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, type=type, account=account)
    result = query.first()
    return result is not None


@transactional_session
def get_auth_token_user_pass(account, username, password, ip=None, session=None):
    """Authenticate a Rucio account temporarily via username and password.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param ip: IP address of the client.
    :param session: The database session in use.

    :returns: Authentication token as a 32 character hex string."""

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    result = session.query(models.Identity).filter_by(identity=username, type='userpass').first()

    db_salt = result['salt']
    db_password = result['password']

    if db_password != hashlib.sha256('%s%s' % (db_salt, password)).hexdigest():
        return None

    # get account name
    result = session.query(models.IdentityAccountAssociation).filter_by(identity=username, type='userpass').first()
    db_account = result['account']

    # create new rucio-auth-token for account
    token = str(uuid.uuid4()).replace('-', '')

    session.add(models.Authentication(account=db_account, token=token, ip=ip))

    return token


@transactional_session
def get_auth_token_x509(account, dn, ip=None, session=None):
    """Authenticate a Rucio account temporarily via an x509 certificate.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param ip: IP address of the client.
    :param session: The database session in use.

    :returns: Authentication token as a 32 character hex string."""

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    session.query(models.Identity).filter_by(identity=dn, type='x509').first()

    # create new rucio-auth-token for account
    token = str(uuid.uuid4()).replace('-', '')

    session.add(models.Authentication(account=account, token=token, ip=ip))

    return token


@transactional_session
def get_auth_token_gss(account, gsstoken, ip=None, session=None):
    """Authenticate a Rucio account temporarily via a GSS token.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param gsscred: GSS principal@REALM
    :param ip: IP address of the client.
    :param session: The database session in use.

    :returns: Authentication token as a 32 character hex string."""

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    session.query(models.Identity).filter_by(identity=gsstoken, type='gsstoken').first()

    # create new rucio-auth-token for account
    token = str(uuid.uuid4()).replace('-', '')

    session.add(models.Authentication(account=account, token=token, ip=ip))

    return token


@read_session
def validate_auth_token(token, session=None):
    """Validate an authentication token.

    :param account: Account identifier.
    :param token: Authentication token as a 32 character hex string.
    :param session: The database session in use.

    :returns: Tuple(account name, Datetime(expected expiry time)) if successful, None otherwise."""

    # Be gentle with bash variables, there can be whitespace
    if token is not None:
        token = token.strip()

    q = session.query(models.Authentication.account, models.Authentication.lifetime).filter(models.Authentication.token == token, models.Authentication.lifetime > datetime.datetime.utcnow())

    r = q.all()

    if r is not None and r != []:
        return {'account': r[0][0], 'lifetime': r[0][1]}

    return None
