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

import hashlib
import os

from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.core.account import account_exists
from rucio.db import models
from rucio.db.session import read_session, transactional_session


class identity_type:
    """ Enumerated type for identity type """
    # As the corresponding column on the db is of type enum, no integers are used
    x509 = 'x509'
    gss = 'gss'
    userpass = 'userpass'


@transactional_session
def add_identity(identity, type, password=None, session=None):
    """
    Creates a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass)
    :param password: If type==userpass, this sets the password.
    :param session: The database session in use.
    """

    if type == identity_type.userpass and password is None:
        raise exception.IdentityError('You must provide a password!')

    new_id = models.Identity()
    new_id.update({'identity': identity, 'type': type})

    if type == identity_type.userpass and password is not None:
        salt = os.urandom(256)  # make sure the salt has the length of the hash
        password = hashlib.sha256('%s%s' % (salt, password)).hexdigest()  # hash it
        new_id.update({'salt': salt, 'password': password})

    try:
        new_id.save(session=session)
    except IntegrityError:
        session.rollback()
        raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))

    session.commit()


@transactional_session
def del_identity(identity, type, session=None):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param session: The database session in use.
    """

    id = session.query(models.Identity).filter_by(identity=identity, type=type).first()

    if id is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))

    id.delete(session)
    session.commit()


@transactional_session
def add_account_identity(identity, type, account, default=False, session=None):
    """
    Adds a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param default: If True, the account should be used by default with the provided identity.
    :param session: The database session in use.
    """
    if not account_exists(account, session=session):
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


@transactional_session
def del_account_identity(identity, type, account, session=None):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param session: The database session in use.
    """

    aid = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, type=type, account=account).first()

    if aid is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))

    aid.delete(session)
    session.commit()


@read_session
def list_identities(session=None, **kwargs):
    """
    Returns a list of all identities.

    :param session: The database session in use.

    returns: A list of all identities.
    """

    id_list = []

    for id in session.query(models.Identity).order_by(models.Identity.identity):
        id_list.append((id.identity, id.type))

    return id_list
