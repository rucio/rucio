# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2017
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

import hashlib
import os
from re import match

from sqlalchemy import asc
from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.core.account import account_exists
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_identity(identity, type_, email, password=None, session=None):
    """
    Creates a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type_: The type of the authentication (x509, gss, userpass, ssh, saml, oidc)
    :param email: The Email address associated with the identity.
    :param password: If type==userpass, this sets the password.
    :param session: The database session in use.
    """

    if type_ == IdentityType.USERPASS and password is None:
        raise exception.IdentityError('You must provide a password!')

    new_id = models.Identity()
    new_id.update({'identity': identity, 'identity_type': type_, 'email': email})

    if type_ == IdentityType.USERPASS:
        salt = os.urandom(255)  # make sure the salt has the length of the hash
        salted_password = salt + password.encode()
        password = hashlib.sha256(salted_password).hexdigest()  # hash it
        new_id.update({'salt': salt, 'password': password, 'email': email})
    try:
        new_id.save(session=session)
    except IntegrityError as e:
        if match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', e.args[0]):
            raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type_))
        raise exception.DatabaseException(str(e))


@transactional_session
def del_identity(identity, type_, session=None):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type_: The type of the authentication (x509, gss, userpass, saml, oidc).
    :param session: The database session in use.
    """

    id_ = session.query(models.Identity).filter_by(identity=identity, identity_type=type_).first()
    if id_ is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type_))
    id_.delete(session=session)


@transactional_session
def add_account_identity(identity, type_, account, email, default=False, password=None, session=None):
    """
    Adds a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type_: The type of the authentication (x509, gss, userpass, ssh, saml, oidc).
    :param account: The account name.
    :param email: The Email address associated with the identity.
    :param default: If True, the account should be used by default with the provided identity.
    :param password: Password if type is userpass.
    :param session: The database session in use.
    """
    if not account_exists(account, session=session):
        raise exception.AccountNotFound('Account \'%s\' does not exist.' % account)

    id_ = session.query(models.Identity).filter_by(identity=identity, identity_type=type_).first()
    if id_ is None:
        add_identity(identity=identity, type_=type_, email=email, password=password, session=session)
        id_ = session.query(models.Identity).filter_by(identity=identity, identity_type=type_).first()

    iaa = models.IdentityAccountAssociation(identity=id_.identity, identity_type=id_.identity_type, account=account,
                                            is_default=default)

    try:
        iaa.save(session=session)
    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-00001: unique constraint.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*UNIQUE constraint failed.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.*columns? .*not unique.*', error.args[0]):
            raise exception.Duplicate('Identity pair \'%s\',\'%s\' already exists!' % (identity, type_))


@read_session
def exist_identity_account(identity, type_, account, session=None):
    """
    Check if an identity is mapped to an account.

    :param identity: The user identity as string.
    :param type_: The type of identity as a string, e.g. userpass, x509, gss, saml, oidc ...
    :param account: The account as an InternalAccount.
    :param session: The database session in use.

    :returns: True if identity is mapped to account, otherwise False
    """
    return session.query(models.IdentityAccountAssociation).filter_by(identity=identity,
                                                                      identity_type=type_,
                                                                      account=account).first() is not None


@read_session
def get_default_account(identity, type_, oldest_if_none=False, session=None):
    """
    Retrieves the default account mapped to an identity.

    :param identity: The identity key name. For example, x509DN, or a username.
    :param type_: The type of the authentication (x509, gss, userpass, saml, oidc).
    :param oldest_if_none: If True and no default account it found the oldes known
                           account of that identity will be chosen, if False and
                           no default account is found, exception will be raised.
    :param session: The database session to use.
    :returns: The default account name, None otherwise.
    """

    tmp = session.query(models.IdentityAccountAssociation).filter_by(identity=identity,
                                                                     identity_type=type_,
                                                                     is_default=True).first()
    if tmp is None:
        if oldest_if_none:
            tmp = session.query(models.IdentityAccountAssociation)\
                         .filter_by(identity=identity, identity_type=type_)\
                         .order_by(asc(models.IdentityAccountAssociation.created_at)).first()
            if tmp is None:
                raise exception.IdentityError('There is no account for identity (%s, %s)' % (identity, type_))
        else:
            raise exception.IdentityError('There is no default account for identity (%s, %s)' % (identity, type_))

    return tmp.account


@transactional_session
def del_account_identity(identity, type_, account, session=None):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type_: The type of the authentication (x509, gss, userpass, saml, oidc).
    :param account: The account name.
    :param session: The database session in use.
    """
    aid = session.query(models.IdentityAccountAssociation).filter_by(identity=identity, identity_type=type_, account=account).first()
    if aid is None:
        raise exception.IdentityError('Identity (\'%s\',\'%s\') does not exist!' % (identity, type_))
    aid.delete(session=session)


@read_session
def list_identities(session=None, **kwargs):
    """
    Returns a list of all identities.

    :param session: The database session in use.

    returns: A list of all identities.
    """

    id_list = []

    for id_ in session.query(models.Identity).order_by(models.Identity.identity):
        id_list.append((id_.identity, id_.identity_type))

    return id_list


@read_session
def list_accounts_for_identity(identity, type_, session=None):
    """
    Returns a list of all accounts for an identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type_: The type of the authentication (x509, gss, userpass, saml, oidc).
    :param session: The database session in use.

    returns: A list of all accounts for the identity.
    """

    account_list = []

    for account, in session.query(models.IdentityAccountAssociation.account).filter_by(identity=identity, identity_type=type_):
        account_list.append(account)

    return account_list
