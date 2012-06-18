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

""" Only for testing """
engine = create_engine(config_get('database', 'default'))
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again

session = sessionmaker(bind=engine, autocommit=True, expire_on_commit=False)


class account_status:
    """ Enumerated type for account status """
    # As the corresponding column on the db is of type enum, no integers are used
    active = 'active'
    inactive = 'inactive'
    disabled = 'disabled'
    not_exist = 'not_exist'


def get_session():
    return scoped_session(session)


def add_account(accountName, accountType):
    """ Add an account with the given account name and type.

    :param accountName: the name of the new account.
    :param accountType: the type of the new account.
    """
    session = get_session()

    with session.begin():

        values = {}
        values['account'] = accountName
        values['type'] = accountType
        values['status'] = account_status.active
        new_account = models.Account()
        new_account.update(values)
        try:
            new_account.save(session=session)
        except IntegrityError, e:
            raise exception.Duplicate('Account ID \'%s\' already exists!' % values['account'])
        finally:
            session.flush()


def account_exists(accountName):
    """ Checks to see if account exists. This procedure does not check it's status.

    :param accountName: Name of the account.
    :returns: True if found, otherwise false.
    """

    session = get_session()
    return True if session.query(models.Account).filter_by(account=accountName).first() else False


def get_account(accountName):
    """ Returns an account for the given account name.

    :param accountName: the name of the account.
    :returns: a dict with all information for the account.
    """
    session = get_session()

    result = None
    with session.begin():
        result = session.query(models.Account).filter_by(account=accountName).first()

    if result is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % accountName)
    return result


def del_account(accountName):
    """ Disable an account with the given account name.

    :param accountName: the account name.
    """
    session = get_session()

    account = None
    with session.begin():
        account = session.query(models.Account).filter_by(account=accountName).first()

        if account is None:
            raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

        account.delete(session)


def get_account_status(accountName):
    """ Returns the state of the account.

    :param accountName: Name of the account.
    """

    session = get_session()
    acc_details = session.query(models.Account).filter_by(account=accountName).one()
    return acc_details.status


def set_account_status(accountName, status):
    """ Set the status of an account.

    :param accountName: Name of the account.
    :param status: The status for the account.
    """

    session = get_session()
    session.begin()
    session.query(models.Account).filter_by(account=accountName).update({'status': status})
    session.commit()


def list_accounts():
    """ Returns a list of all account names.

    returns: a list of all account names.
    """
    session = get_session()
    account_list = []

    with session.begin():
        for account in session.query(models.Account).order_by(models.Account.account):
            account_list.append(account.account)

    return account_list
