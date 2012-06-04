# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import hashlib
import os

from sqlalchemy import create_engine, update
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.account import account_exists
from rucio.db import models1 as models

""" Only for testing """
engine = create_engine(config_get('database', 'default'))
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again

session = sessionmaker(bind=engine, autocommit=True, expire_on_commit=False)


class identity_type:
    """ Enumerated type for identity type """
    # As the corresponding column on the db is of type enum, no integers are used
    x509 = 'x509'
    gss = 'gss'
    userpass = 'userpass'


def get_session():
    return scoped_session(session)


def add_identity(identity, type, password=None):
    """
    Creates a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass)
    :param password: If type==userpass, this sets the password.
    """

    if type == identity_type.userpass and password is None:
        raise exception.IdentityError('You must provide a password!')

    new_id = models.Identity()
    new_id.update({'identity': identity,
                   'type': type})

    if type == identity_type.userpass and password is not None:
        salt = os.urandom(256)  # make sure the salt has the length of the hash
        password = hashlib.sha256('%s%s' % (salt, password)).hexdigest()  # hash it
        new_id.update({'salt': salt,
                       'password': password})

    session = get_session()
    with session.begin():
        try:
            new_id.save(session=session)
        except IntegrityError, e:
            raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))
        finally:
            session.flush()


def del_identity(identity, type):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    """

    id = None

    session = get_session()
    with session.begin():
        id = session.query(models.Identity).filter_by(identity=identity, type=type).first()

        if id is None:
            raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))

        id.delete(session)


def add_account_identity(identity, type, account, default=False):
    """
    Adds a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param default: If True, the account should be used by default with the provided identity.
    """

    if not account_exists(account):
        raise exception.AccountNotFound('Account \'%s\' does not exist.' % account)

    new_aid = models.IdentityAccountAssociation()
    new_aid['identity'] = identity
    new_aid['type'] = type
    new_aid['account'] = account

    session = get_session()
    with session.begin():
        try:
            new_aid.save(session=session)
        except IntegrityError, e:
            raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))
        finally:
            session.flush()


def del_account_identity(identity, type, account):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    """

    aid = None

    session = get_session()
    with session.begin():
        aid = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, type=type, account=account).first()

        if aid is None:
            raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))

        aid.delete(session)


def list_identities(**kwargs):
    """
    Returns a list of all identities.

    returns: A list of all identities.
    """

    id_list = []

    session = get_session()
    with session.begin():
        for id in session.query(models.Identity).order_by(models.Identity.identity):
            id_list.append((id.identity, id.type))

    return id_list
