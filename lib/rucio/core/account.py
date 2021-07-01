# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from datetime import datetime
from enum import Enum
from re import match
from traceback import format_exc

from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import exc

import rucio.core.account_counter
import rucio.core.rse

from rucio.common import exception
from rucio.common.config import config_get_bool
from rucio.core.vo import vo_exists
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountStatus, AccountType
from rucio.db.sqla.session import read_session, transactional_session, stream_session

from six import string_types


@transactional_session
def add_account(account, type, email, session=None):
    """ Add an account with the given account name and type.

    :param account: the name of the new account.
    :param type: the type of the new account.
    :param email: The Email address associated with the account.
    :param session: the database session in use.
    """
    vo = account.vo
    if not vo_exists(vo=vo, session=session):
        raise exception.VONotFound('VO {} not found'.format(vo))

    # Reserve the name 'super_root' for multi_vo admins
    if account.external == 'super_root':
        if not (vo == 'def' and config_get_bool('common', 'multi_vo', raise_exception=False, default=False)):
            raise exception.UnsupportedAccountName('The name "%s" cannot be used.' % account.external)

    new_account = models.Account(account=account, account_type=type, email=email,
                                 status=AccountStatus.ACTIVE)
    try:
        new_account.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('Account ID \'%s\' already exists!' % account)
    # Create the account counters for this account
    rucio.core.account_counter.create_counters_for_new_account(account=account, session=session)


@read_session
def account_exists(account, session=None):
    """ Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account.
    :param session: the database session in use.

    :returns: True if found, otherwise false.
    """

    query = session.query(models.Account).filter_by(account=account, status=AccountStatus.ACTIVE)

    return True if query.first() else False


@read_session
def get_account(account, session=None):
    """ Returns an account for the given account name.

    :param account: the name of the account.
    :param session: the database session in use.

    :returns: a dict with all information for the account.
    """

    query = session.query(models.Account).filter_by(account=account)

    result = query.first()
    if result is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)
    return result


@transactional_session
def del_account(account, session=None):
    """ Disable an account with the given account name.

    :param account: the account name.
    :param session: the database session in use.
    """
    query = session.query(models.Account).filter_by(account=account).filter_by(status=AccountStatus.ACTIVE)
    try:
        account = query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

    account.update({'status': AccountStatus.DELETED, 'deleted_at': datetime.utcnow()})


@transactional_session
def update_account(account, key, value, session=None):
    """ Update a property of an account.

    :param account: Name of the account.
    :param key: Account property like status.
    :param value: Property value.
    :param session: the database session in use.
    """
    query = session.query(models.Account).filter_by(account=account)
    try:
        account = query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)
    if key == 'status':
        if isinstance(value, string_types):
            value = AccountStatus[value]
        if value == AccountStatus.SUSPENDED:
            query.update({'status': value, 'suspended_at': datetime.utcnow()})
        elif value == AccountStatus.ACTIVE:
            query.update({'status': value, 'suspended_at': None})
    else:
        query.update({key: value})


@stream_session
def list_accounts(filter={}, session=None):
    """ Returns a list of all account names.

    :param filter: Dictionary of attributes by which the input data should be filtered
    :param session: the database session in use.

    returns: a list of all account names.
    """
    query = session.query(models.Account.account, models.Account.account_type,
                          models.Account.email).filter_by(status=AccountStatus.ACTIVE)
    for filter_type in filter:
        if filter_type == 'account_type':
            if isinstance(filter['account_type'], string_types):
                query = query.filter_by(account_type=AccountType[filter['account_type']])
            elif isinstance(filter['account_type'], Enum):
                query = query.filter_by(account_type=filter['account_type'])

        elif filter_type == 'identity':
            query = query.join(models.IdentityAccountAssociation, models.Account.account == models.IdentityAccountAssociation.account).\
                filter(models.IdentityAccountAssociation.identity == filter['identity'])

        elif filter_type == 'account':
            if '*' in filter['account'].internal:
                account_str = filter['account'].internal.replace('*', '%')
                query = query.filter(models.Account.account.like(account_str))
            else:
                query = query.filter_by(account=filter['account'])
        else:
            query = query.join(models.AccountAttrAssociation, models.Account.account == models.AccountAttrAssociation.account).\
                filter(models.AccountAttrAssociation.key == filter_type).\
                filter(models.AccountAttrAssociation.value == filter[filter_type])

    for account, account_type, email in query.order_by(models.Account.account).yield_per(25):
        yield {'account': account, 'type': account_type, 'email': email}


@read_session
def list_identities(account, session=None):
    """
    List all identities on an account.

    :param account: The account name.
    :param session: the database session in use.
    """
    identity_list = list()

    query = session.query(models.Account).filter_by(account=account).filter_by(status=AccountStatus.ACTIVE)
    try:
        query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

    query = session.query(models.IdentityAccountAssociation, models.Identity)\
                   .join(models.Identity, and_(models.Identity.identity == models.IdentityAccountAssociation.identity,
                                               models.Identity.identity_type == models.IdentityAccountAssociation.identity_type))\
                   .filter(models.IdentityAccountAssociation.account == account)
    for identity in query:
        identity_list.append({'type': identity[0].identity_type, 'identity': identity[0].identity, 'email': identity[1].email})

    return identity_list


@read_session
def list_account_attributes(account, session=None):
    """
    Get all attributes defined for an account.

    :param account: the account name to list the scopes of.
    :param session: The database session in use.

    :returns: a list of all key, value pairs for this account.
    """
    attr_list = []
    query = session.query(models.Account).filter_by(account=account).filter_by(status=AccountStatus.ACTIVE)
    try:
        query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound("Account ID '{0}' does not exist".format(account))

    query = session.query(models.AccountAttrAssociation).filter_by(account=account)
    for attr in query:
        attr_list.append({'key': attr.key, 'value': attr.value})

    return attr_list


@read_session
def has_account_attribute(account, key, session=None):
    """
    Indicates whether the named key is present for the account.

    :param account: the account name to list the scopes of.
    :param key: the key for the attribute.
    :param session: The database session in use.

    :returns: True or False
    """
    if session.query(models.AccountAttrAssociation.value).filter_by(account=account, key=key).first():
        return True
    return False


@transactional_session
def add_account_attribute(account, key, value, session=None):
    """
    Add an attribute for the given account name.

    :param key: the key for the new attribute.
    :param value: the value for the new attribute.
    :param account: the account to add the attribute to.
    :param session: The database session in use.
    """

    query = session.query(models.Account).filter_by(account=account, status=AccountStatus.ACTIVE)

    try:
        query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound("Account ID '{0}' does not exist".format(account))

    new_attr = models.AccountAttrAssociation(account=account, key=key, value=value)
    try:
        new_attr.save(session=session)
    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-00001: unique constraint.*ACCOUNT_ATTR_MAP_PK.*violated.*', error.args[0]) \
           or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
           or match('.*IntegrityError.*UNIQUE constraint failed: account_attr_map.account, account_attr_map.key.*', error.args[0]) \
           or match('.*IntegrityError.*columns? account.*key.*not unique.*', error.args[0]) \
           or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
           or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]):
            raise exception.Duplicate('Key {0} already exist for account {1}!'.format(key, account))
    except Exception:
        raise exception.RucioException(str(format_exc()))


@transactional_session
def del_account_attribute(account, key, session=None):
    """
    Add an attribute for the given account name.

    :param account: the account to add the attribute to.
    :param key: the key for the new attribute.
    :param session: The database session in use.
    """
    aid = session.query(models.AccountAttrAssociation).filter_by(key=key, account=account).first()
    if aid is None:
        raise exception.AccountNotFound('Attribute ({0}) does not exist for the account {1}!'.format(key, account))
    aid.delete(session=session)


@read_session
def get_usage(rse_id, account, session=None):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param account:          The account name.
    :param session:          The database session in use.
    :returns:                A dictionary with total and bytes.
    """

    try:
        counter = session.query(models.AccountUsage).filter_by(rse_id=rse_id, account=account).one()
        return {'bytes': counter.bytes, 'files': counter.files, 'updated_at': counter.updated_at}
    except exc.NoResultFound:
        return {'bytes': 0, 'files': 0, 'updated_at': None}


@read_session
def get_all_rse_usages_per_account(account, session=None):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param account:          The account name.
    :param session:          The database session in use.
    :returns:                A dictionary with total and bytes.
    """

    try:
        return [result.to_dict() for result in session.query(models.AccountUsage).filter_by(account=account).all()]
    except exc.NoResultFound:
        return []


@read_session
def get_usage_history(rse_id, account, session=None):
    """
    Returns historical values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param account:          The account name.
    :param session:          The database session in use.
    :returns:                A dictionary with total and bytes.
    """

    result = []
    AccountUsageHistory = models.AccountUsageHistory
    try:
        query = session.query(AccountUsageHistory).filter_by(rse_id=rse_id, account=account).order_by(AccountUsageHistory.updated_at)
        for row in query.all():
            result.append({'bytes': row.bytes, 'files': row.files, 'updated_at': row.updated_at})
    except exc.NoResultFound:
        raise exception.CounterNotFound('No usage can be found for account %s on RSE %s' % (account, rucio.core.rse.get_rse_name(rse_id=rse_id, session=session)))
    return result
