# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import hashlib
import os

from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.core.account import account_exists
from rucio.db import models1 as models
from rucio.db.session import get_session

session = get_session()


class identity_type:
    """ Enumerated type for identity type """
    # As the corresponding column on the db is of type enum, no integers are used
    x509 = 'x509'
    gss = 'gss'
    userpass = 'userpass'


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

    try:
        new_id.save(session=session)
    except IntegrityError:
        session.rollback()
        raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))

    session.commit()


def del_identity(identity, type):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    """

    id = session.query(models.Identity).filter_by(identity=identity, type=type).first()

    if id is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))

    id.delete(session)
    session.commit()


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

    id = models.Identity(identity=identity, type=type)
    iaa = models.IdentityAccountAssociation(identity=id.identity, type=id.type, account=account)

    try:
        id.save(session=session)
    except IntegrityError:
        session.rollback()

    try:
        iaa.save(session=session)
    except IntegrityError:
        session.rollback()
        raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))

    session.commit()


def del_account_identity(identity, type, account):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    """

    aid = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, type=type, account=account).first()

    if aid is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))

    aid.delete(session)
    session.commit()


def list_identities(**kwargs):
    """
    Returns a list of all identities.

    returns: A list of all identities.
    """

    id_list = []

    for id in session.query(models.Identity).order_by(models.Identity.identity):
        id_list.append((id.identity, id.type))

    return id_list
