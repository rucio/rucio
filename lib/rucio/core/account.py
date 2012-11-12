# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import exc

from rucio.common import exception
from rucio.db import models
from rucio.db.session import get_session

session = get_session()


class account_status:
    """ Enumerated type for account status """
    # As the corresponding column on the db is of type enum, no integers are used
    active = 'active'
    inactive = 'inactive'
    disabled = 'disabled'
    not_exist = 'not_exist'


def add_account(account_name, account_type):
    """ Add an account with the given account name and type.

    :param account_name: the name of the new account.
    :param account_type: the type of the new account.
    """

    values = {}
    values['account'] = account_name
    values['type'] = account_type
    values['status'] = account_status.active
    new_account = models.Account()

    new_account.update(values)

    try:
        new_account.save(session=session)
    except IntegrityError:
        session.rollback()
        raise exception.Duplicate('Account ID \'%s\' already exists!' % values['account'])

    session.commit()


def account_exists(account_name):
    """ Checks to see if account exists. This procedure does not check it's status.

    :param account_name: Name of the account.
    :returns: True if found, otherwise false.
    """

    query = session.query(models.Account).filter_by(account=account_name)

    return True if query.first() else False


def get_account(account_name):
    """ Returns an account for the given account name.

    :param account_name: the name of the account.
    :returns: a dict with all information for the account.
    """

    query = session.query(models.Account).filter_by(account=account_name)

    result = query.first()
    if result is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account_name)
    return result


def del_account(account_name):
    """ Disable an account with the given account name.

    :param account_name: the account name.
    """

    query = session.query(models.Account).filter_by(account=account_name).filter_by(deleted=False)

    try:
        account = query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account_name)

    account.delete(session=session)
    session.commit()


def get_account_status(account_name):
    """ Returns the state of the account.

    :param account_name: Name of the account.
    """

    query = session.query(models.Account).filter_by(account=account_name)

    acc_details = query.one()
    return acc_details.status


def set_account_status(account_name, status):
    """ Set the status of an account.

    :param account_name: Name of the account.
    :param status: The status for the account.
    """

    session.query(models.Account).filter_by(account=account_name).update({'status': status})
    session.commit()


def list_accounts():
    """ Returns a list of all account names.

    returns: a list of all account names.
    """

    account_list = []

    query = session.query(models.Account).filter_by(deleted=False)

    for account in query.order_by(models.Account.account):
        account_list.append(account.account)

    return account_list


def list_identities(account_name):
    """
    List all identities on an account.

    :param account_name: The account name.
    """
    identity_list = list()

    query = session.query(models.Account).filter_by(account=account_name).filter_by(deleted=False)

    try:
        query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account_name)

    query = session.query(models.IdentityAccountAssociation).filter_by(account=account_name)
    for identity in query:
        identity_list.append({'type': identity.type, 'identity': identity.identity})

    return identity_list
