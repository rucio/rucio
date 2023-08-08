# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from datetime import datetime
from enum import Enum
from re import match
from traceback import format_exc
from typing import TYPE_CHECKING

from sqlalchemy import select, and_
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

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_account(account, type_, email, *, session: "Session"):
    """ Add an account with the given account name and type.

    :param account: the name of the new account.
    :param type_: the type of the new account.
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

    new_account = models.Account(account=account, account_type=type_, email=email,
                                 status=AccountStatus.ACTIVE)
    try:
        new_account.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('Account ID \'%s\' already exists!' % account)


@read_session
def account_exists(account, *, session: "Session"):
    """ Checks to see if account exists and is active.

    :param account: Name of the account.
    :param session: the database session in use.

    :returns: True if found, otherwise false.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account,
        models.Account.status == AccountStatus.ACTIVE
    )
    return session.execute(query).scalar() is not None


@read_session
def get_account(account, *, session: "Session"):
    """ Returns an account for the given account name.

    :param account: the name of the account.
    :param session: the database session in use.

    :returns: a dict with all information for the account.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account
    )

    result = session.execute(query).scalar()
    if result is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)
    return result


@transactional_session
def del_account(account, *, session: "Session"):
    """ Disable an account with the given account name.

    :param account: the account name.
    :param session: the database session in use.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account,
        models.Account.status == AccountStatus.ACTIVE
    )
    try:
        account = session.execute(query).scalar_one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

    account.update({'status': AccountStatus.DELETED, 'deleted_at': datetime.utcnow()})


@transactional_session
def update_account(account, key, value, *, session: "Session"):
    """ Update a property of an account.

    :param account: Name of the account.
    :param key: Account property like status.
    :param value: Property value.
    :param session: the database session in use.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account
    )
    try:
        account = session.execute(query).scalar_one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)
    if key == 'status':
        if isinstance(value, str):
            value = AccountStatus[value]
        if value == AccountStatus.SUSPENDED:
            account.update({'status': value, 'suspended_at': datetime.utcnow()})
        elif value == AccountStatus.ACTIVE:
            account.update({'status': value, 'suspended_at': None})
    else:
        account.update({key: value})


@stream_session
def list_accounts(filter_=None, *, session: "Session"):
    """ Returns a list of all account names.

    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param session: the database session in use.

    returns: a list of all account names.
    """
    if filter_ is None:
        filter_ = {}
    query = select(
        models.Account.account,
        models.Account.account_type,
        models.Account.email
    ).where(
        models.Account.status == AccountStatus.ACTIVE
    )
    for filter_type in filter_:
        if filter_type == 'account_type':
            if isinstance(filter_['account_type'], str):
                query = query.where(
                    models.Account.account_type == AccountType[filter_['account_type']]
                )
            elif isinstance(filter_['account_type'], Enum):
                query = query.where(
                    models.Account.account_type == filter_['account_type']
                )

        elif filter_type == 'identity':
            query = query.join(
                models.IdentityAccountAssociation,
                models.Account.account == models.IdentityAccountAssociation.account
            ).where(
                models.IdentityAccountAssociation.identity == filter_['identity']
            )

        elif filter_type == 'account':
            if '*' in filter_['account'].internal:
                account_str = filter_['account'].internal.replace('*', '%')
                query = query.where(
                    models.Account.account.like(account_str)
                )
            else:
                query = query.where(
                    models.Account.account == filter_['account']
                )
        else:
            query = query.join(
                models.AccountAttrAssociation,
                models.Account.account == models.AccountAttrAssociation.account
            ).where(
                models.AccountAttrAssociation.key == filter_type,
                models.AccountAttrAssociation.value == filter_[filter_type]
            )
    query = query.order_by(models.Account.account)

    for account, account_type, email in session.execute(query).yield_per(25):
        yield {'account': account, 'type': account_type, 'email': email}


@read_session
def list_identities(account, *, session: "Session"):
    """
    List all identities on an account.

    :param account: The account name.
    :param session: the database session in use.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account,
        models.Account.status == AccountStatus.ACTIVE
    )
    try:
        session.execute(query).scalar_one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

    query = select(
        models.IdentityAccountAssociation.identity_type.label('type'),
        models.IdentityAccountAssociation.identity,
        models.Identity.email
    ).join(
        models.Identity,
        and_(
            models.Identity.identity == models.IdentityAccountAssociation.identity,
            models.Identity.identity_type == models.IdentityAccountAssociation.identity_type
        )
    ).where(
        models.IdentityAccountAssociation.account == account
    )
    return [row._asdict() for row in session.execute(query)]


@read_session
def list_account_attributes(account, *, session: "Session"):
    """
    Get all attributes defined for an account.

    :param account: the account name to list the scopes of.
    :param session: The database session in use.

    :returns: a list of all key, value pairs for this account.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account,
        models.Account.status == AccountStatus.ACTIVE
    )
    try:
        session.execute(query).scalar_one()
    except exc.NoResultFound:
        raise exception.AccountNotFound("Account ID '{0}' does not exist".format(account))

    query = select(
        models.AccountAttrAssociation.key,
        models.AccountAttrAssociation.value
    ).where(
        models.AccountAttrAssociation.account == account
    )
    return [row._asdict() for row in session.execute(query)]


@read_session
def has_account_attribute(account, key, *, session: "Session"):
    """
    Indicates whether the named key is present for the account.

    :param account: the account name to list the scopes of.
    :param key: the key for the attribute.
    :param session: The database session in use.

    :returns: True or False
    """
    query = select(
        models.AccountAttrAssociation.value
    ).where(
        models.AccountAttrAssociation.account == account,
        models.AccountAttrAssociation.key == key
    )
    return session.execute(query).scalar() is not None


@transactional_session
def add_account_attribute(account, key, value, *, session: "Session"):
    """
    Add an attribute for the given account name.

    :param key: the key for the new attribute.
    :param value: the value for the new attribute.
    :param account: the account to add the attribute to.
    :param session: The database session in use.
    """
    query = select(
        models.Account
    ).where(
        models.Account.account == account,
        models.Account.status == AccountStatus.ACTIVE
    )
    try:
        session.execute(query).scalar_one()
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
def del_account_attribute(account, key, *, session: "Session"):
    """
    Add an attribute for the given account name.

    :param account: the account to add the attribute to.
    :param key: the key for the new attribute.
    :param session: The database session in use.
    """
    query = select(
        models.AccountAttrAssociation
    ).where(
        models.AccountAttrAssociation.account == account,
        models.AccountAttrAssociation.key == key
    )
    aid = session.execute(query).scalar()
    if aid is None:
        raise exception.AccountNotFound('Attribute ({0}) does not exist for the account {1}!'.format(key, account))
    aid.delete(session=session)


@read_session
def get_usage(rse_id, account, *, session: "Session"):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param account:          The account name.
    :param session:          The database session in use.
    :returns:                A dictionary {'bytes', 'files', 'updated_at'}
    """
    query = select(
        models.AccountUsage.bytes,
        models.AccountUsage.files,
        models.AccountUsage.updated_at
    ).where(
        models.AccountUsage.rse_id == rse_id,
        models.AccountUsage.account == account
    )
    try:
        return session.execute(query).one()._asdict()
    except exc.NoResultFound:
        return {'bytes': 0, 'files': 0, 'updated_at': None}


@read_session
def get_all_rse_usages_per_account(account, *, session: "Session"):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param account:          The account name.
    :param session:          The database session in use.
    :returns:                List of dicts with :py:class:`models.AccountUsage` items
    """
    query = select(
        models.AccountUsage
    ).where(
        models.AccountUsage.account == account
    )
    try:
        return [result.to_dict() for result in session.execute(query).scalars()]
    except exc.NoResultFound:
        return []


@read_session
def get_usage_history(rse_id, account, *, session: "Session"):
    """
    Returns historical values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param account:          The account name.
    :param session:          The database session in use.
    :returns:                A dictionary {'bytes', 'files', 'updated_at'}
    """
    query = select(
        models.AccountUsageHistory.bytes,
        models.AccountUsageHistory.files,
        models.AccountUsageHistory.updated_at
    ).where(
        models.AccountUsageHistory.rse_id == rse_id,
        models.AccountUsageHistory.account == account
    ).order_by(
        models.AccountUsageHistory.updated_at
    )
    try:
        return [row._asdict() for row in session.execute(query)]
    except exc.NoResultFound:
        raise exception.CounterNotFound('No usage can be found for account %s on RSE %s' % (account, rucio.core.rse.get_rse_name(rse_id=rse_id, session=session)))
    return []
