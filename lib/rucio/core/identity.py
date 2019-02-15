# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2015, 2017
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

import hashlib
import os

from re import match

from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.core.account import account_exists
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_identity(identity, type, email, password=None, session=None):
    """
    Creates a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass, ssh)
    :param email: The Email address associated with the identity.
    :param password: If type==userpass, this sets the password.
    :param session: The database session in use.
    """

    if type == IdentityType.USERPASS and password is None:
        raise exception.IdentityError('You must provide a password!')

    new_id = models.Identity()
    new_id.update({'identity': identity, 'identity_type': type, 'email': email})

    if type == IdentityType.USERPASS and password is not None:
        salt = os.urandom(255)  # make sure the salt has the length of the hash
        password = hashlib.sha256('%s%s' % (salt, password.encode('utf-8'))).hexdigest()  # hash it
        new_id.update({'salt': salt, 'password': password, 'email': email})
    try:
        new_id.save(session=session)
    except IntegrityError as e:
        if match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', e.args[0]):
            raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))
        raise exception.DatabaseException(str(e))


@transactional_session
def del_identity(identity, type, session=None):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param session: The database session in use.
    """

    id = session.query(models.Identity).filter_by(identity=identity, identity_type=type).first()
    if id is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))
    id.delete(session=session)


@transactional_session
def add_account_identity(identity, type, account, email, default=False, password=None, session=None):
    """
    Adds a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass, ssh).
    :param account: The account name.
    :param email: The Email address associated with the identity.
    :param default: If True, the account should be used by default with the provided identity.
    :param password: Password if type is userpass.
    :param session: The database session in use.
    """
    if not account_exists(account, session=session):
        raise exception.AccountNotFound('Account \'%s\' does not exist.' % account)

    id = session.query(models.Identity).filter_by(identity=identity, identity_type=type).first()
    if id is None:
        add_identity(identity=identity, type=type, email=email, password=password, session=session)
        id = session.query(models.Identity).filter_by(identity=identity, identity_type=type).first()

    iaa = models.IdentityAccountAssociation(identity=id.identity, identity_type=id.identity_type, account=account)

    try:
        iaa.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type))


@read_session
def get_default_account(identity, type, session=None):
    """
    Retrieves the default account mapped to an identity.

    :param identity: The identity key name. For example, x509DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param session: The database session to use.
    :returns: The default account name, None otherwise.
    """

    tmp = session.query(models.IdentityAccountAssociation).filter_by(identity=identity,
                                                                     identity_type=type,
                                                                     is_default=True).first()
    if tmp is None:
        raise exception.IdentityError('There is no default account for identity (%s, %s)' % (identity, type))

    return tmp.account


@transactional_session
def del_account_identity(identity, type, account, session=None):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param session: The database session in use.
    """
    aid = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, identity_type=type, account=account).first()
    if aid is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type))
    aid.delete(session=session)


@read_session
def list_identities(session=None, **kwargs):
    """
    Returns a list of all identities.

    :param session: The database session in use.

    returns: A list of all identities.
    """

    id_list = []

    for id in session.query(models.Identity).order_by(models.Identity.identity):
        id_list.append((id.identity, id.identity_type))

    return id_list


@read_session
def list_accounts_for_identity(identity, type, session=None):
    """
    Returns a list of all accounts for an identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param session: The database session in use.

    returns: A list of all accounts for the identity.
    """

    account_list = []

    for account, in session.query(models.IdentityAccountAssociation.account).filter_by(identity=identity, identity_type=type):
        account_list.append(account)

    return account_list
