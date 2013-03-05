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
    """
    Check if a identity is mapped to an account.

    :param identity: The user identity as string.
    :param type: The type of identity as a string, e.g. userpass, x509, gss...
    :param account: The account identifier as a string.
    :param session: The database session in use.

    :returns: True if identity is mapped to account, otherwise False
    """

    query = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, type=type, account=account)
    result = query.first()
    return result is not None


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

    :returns: Authentication token as a variable-length string.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    result = session.query(models.Identity).filter_by(identity=username, type='userpass').first()

    db_salt = result['salt']
    db_password = result['password']

    if db_password != hashlib.sha256('%s%s' % (db_salt, password)).hexdigest():
        return None

    # get account identifier
    result = session.query(models.IdentityAccountAssociation).filter_by(identity=username, type='userpass').first()
    db_account = result['account']

    # create new rucio-auth-token for account
    tuid = str(uuid.uuid4()).replace('-', '')  # NOQA
    token = '%(account)s-%(username)s-%(appid)s-%(tuid)s' % locals()

    new_token = models.Authentication(account=db_account, token=token, ip=ip)
    new_token.save(session=session)

    return token


@transactional_session
def get_auth_token_x509(account, dn, appid, ip=None, session=None):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.

    The token lifetime is 1 hour.

    :param account: Account identifier as a string.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: Authentication token as a variable-length string.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    session.query(models.Identity).filter_by(identity=dn, type='x509').first()

    # create new rucio-auth-token for account
    tuid = str(uuid.uuid4()).replace('-', '')  # NOQA
    token = '%(account)s-%(dn)s-%(appid)s-%(tuid)s' % locals()

    new_token = models.Authentication(account=account, token=token, ip=ip)
    new_token.save(session=session)

    return token


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

    :returns: Authentication token as a variable-length string.
    """

    # Make sure the account exists
    if not account_exists(account, session=session):
        return None

    session.query(models.Identity).filter_by(identity=gsstoken, type='gsstoken').first()

    # create new rucio-auth-token for account
    tuid = str(uuid.uuid4()).replace('-', '')  # NOQA
    token = '%(account)s-%(gsstoken)s-%(appid)s-%(token)s' % locals()

    new_token = models.Authentication(account=account, token=token, ip=ip)
    new_token.save(session=session)

    return token


@read_session
def validate_auth_token(token, session=None):
    """
    Validate an authentication token.

    :param token: Authentication token as a variable-length string.
    :param session: The database session in use.

    :returns: Tuple(account identifier, token lifetime) if successful, None otherwise.
    """

    # Be gentle with bash variables, there can be whitespace
    if token is not None:
        token = token.strip()
    else:
        return None

    q = session.query(models.Authentication.account, models.Authentication.lifetime).filter(models.Authentication.token == token, models.Authentication.lifetime > datetime.datetime.utcnow())

    r = q.all()

    if r is not None and r != []:
        return {'account': r[0][0], 'lifetime': r[0][1]}

    return None
