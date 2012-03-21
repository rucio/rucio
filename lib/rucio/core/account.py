# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import IntegrityError

from rucio.db import models1 as models
from rucio.common import exception
from rucio.common.config import config_get

""" Only for testing """
engine = create_engine(config_get('database', 'default'))
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again

session = sessionmaker(bind=engine, autocommit=True, expire_on_commit=False)


def get_session():
    return scoped_session(session)


def add_account(accountName, accountType):
    """ add an account with the given account name and type.

    :param accountName: the name of the new account.
    :param accountType: the type of the new account.
    """
    session = get_session()

    with session.begin():

        values = {}
        values['account'] = accountName
        values['type'] = accountType

        new_account = models.Account()

        new_account.update(values)

        try:
            new_account.save(session=session)
        except IntegrityError, e:
            raise exception.Duplicate('Account ID \'%s\' already exists!' % values['account'])
        finally:
            session.flush()


def get_account(accountName):
    """ returns an account for the given account name.

    :param accountName: the name of the account.
    :returns: a dict with all information for the account.
    """
    session = get_session()

    result = None
    with session.begin():
        result = session.query(models.Account).filter_by(account=accountName).first()

    if result is None:
        raise exception.NotFound('Account with ID \'%s\' cannot be found' % accountName)
    return result


def del_account(accountName):
    """ disable an account with the given account name.

    :param accountName: the account name.
    """
    session = get_session()

    account = None
    with session.begin():
        account = session.query(models.Account).filter_by(account=accountName).first()

        if account is None:
            raise exception.NotFound('Account with ID \'%s\' cannot be found' % account)

        account.delete(session)


def list_accounts():
    """ returns a list of all account names.

    returns: a list of all account names.
    """
    session = get_session()
    account_list = []

    with session.begin():
        for account in session.query(models.Account).order_by(models.Account.account):
            account_list.append(account.account)

    return account_list
