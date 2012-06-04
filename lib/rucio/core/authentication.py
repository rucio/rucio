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

from sqlalchemy import create_engine, text, and_, update
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.account import account_exists
from rucio.db import models1 as models


""" Only for testing """
engine = create_engine(config_get('database', 'default'))
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again

session = sessionmaker(bind=engine, autocommit=True, expire_on_commit=False)


def get_session():
    return scoped_session(session)


def get_auth_token_user_pass(account, username, password, ip=None):
    """ Authenticate a Rucio account via username and password. """

    # Make sure the account exists
    if not account_exists(account):
        return None

    session = get_session()
    with session.begin():
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

    return None


def validate_auth_token(account, token):
    """ Validate an authentication token. """

    session = get_session()
    with session.begin():
        q = session.query(models.Authentication.lifetime).filter(and_(models.Authentication.account == account, models.Authentication.token == token, models.Authentication.lifetime > datetime.datetime.utcnow()))

        r = q.all()

        if r is not None and r != []:
            q.update({'lifetime': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)})
            return r[0][0]

    return None
