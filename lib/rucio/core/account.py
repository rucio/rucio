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

from sqlalchemy import create_engine, update
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.db import models1 as models
from rucio.db.session import get_session

session = get_session()


class account_status:
    """ Enumerated type for account status """
    # As the corresponding column on the db is of type enum, no integers are used
    active = 'active'
    inactive = 'inactive'
    disabled = 'disabled'
    not_exist = 'not_exist'


def add_account(accountName, accountType):
    """ Add an account with the given account name and type.

    :param accountName: the name of the new account.
    :param accountType: the type of the new account.
    """

    values = {}
    values['account'] = accountName
    values['type'] = accountType
    values['status'] = account_status.active
    new_account = models.Account()

    new_account.update(values)

    try:
        new_account.save(session=session)
    except IntegrityError, e:
        session.rollback()
        raise exception.Duplicate('Account ID \'%s\' already exists!' % values['account'])

    session.commit()


def account_exists(accountName):
    """ Checks to see if account exists. This procedure does not check it's status.

    :param accountName: Name of the account.
    :returns: True if found, otherwise false.
    """

    return True if session.query(models.Account).filter_by(account=accountName).first() else False


def get_account(accountName):
    """ Returns an account for the given account name.

    :param accountName: the name of the account.
    :returns: a dict with all information for the account.
    """

    result = session.query(models.Account).filter_by(account=accountName).first()

    if result is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % accountName)
    return result


def del_account(accountName):
    """ Disable an account with the given account name.

    :param accountName: the account name.
    """

    account = session.query(models.Account).filter_by(account=accountName).first()

    if account is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

    account.delete(session)
    session.commit()


def get_account_status(accountName):
    """ Returns the state of the account.

    :param accountName: Name of the account.
    """

    acc_details = session.query(models.Account).filter_by(account=accountName).one()
    return acc_details.status


def set_account_status(accountName, status):
    """ Set the status of an account.

    :param accountName: Name of the account.
    :param status: The status for the account.
    """

    session.query(models.Account).filter_by(account=accountName).update({'status': status})
    session.commit()


def list_accounts():
    """ Returns a list of all account names.

    returns: a list of all account names.
    """

    account_list = []

    for account in session.query(models.Account).order_by(models.Account.account):
        account_list.append(account.account)

    return account_list
