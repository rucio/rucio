# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import datetime
import hashlib
import uuid

from rucio.core.account import account_exists
from rucio.db import models1 as models
from rucio.db.session import get_session

session = get_session()


def get_auth_token_user_pass(account, username, password, ip=None):
    """ Authenticate a Rucio account via username and password. """

    # Make sure the account exists
    if not account_exists(account):
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
    session.commit()

    return token


def get_auth_token_x509(account, dn, ip=None):
    """ Authenticate a Rucio account via an x509 subject distinguished name. """

    # Make sure the account exists
    if not account_exists(account):
        return None

    session.query(models.Identity).filter_by(identity=dn, type='x509').first()

    # create new rucio-auth-token for account
    token = str(uuid.uuid4()).replace('-', '')

    session.add(models.Authentication(account=account, token=token, ip=ip))
    session.commit()

    return token


def get_auth_token_gss(account, gsstoken, ip=None):
    """ Authenticate a Rucio account temporarily via a GSS token. """

    # Make sure the account exists
    if not account_exists(account):
        return None

    session.query(models.Identity).filter_by(identity=gsstoken, type='gsstoken').first()

    # create new rucio-auth-token for account
    token = str(uuid.uuid4()).replace('-', '')

    session.add(models.Authentication(account=account, token=token, ip=ip))
    session.commit()

    return token


def validate_auth_token(token):
    """ Validate an authentication token. """

    # Be gentle with bash variables, there can be whitespace
    if token is not None:
        token = token.strip()

    q = session.query(models.Authentication.account, models.Authentication.lifetime).filter(models.Authentication.token == token, models.Authentication.lifetime > datetime.datetime.utcnow())

    r = q.all()

    if r is not None and r != []:
        q.update({'lifetime': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)})
        session.commit()
        return (r[0][0], r[0][1])

    return None
