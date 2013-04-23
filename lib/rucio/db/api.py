# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann,  <thomas.beermann@cern.ch> , 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import logging

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from rucio.db import models
from rucio.common import exception
from gettext import gettext as _

_ENGINE = None
_MAKER = None
BASE = models.BASE
logger = logging.getLogger(__name__)
sa_logger = None

db_opts = {
    'sql_idle_timeout': 6,
    'sql_connection': 'sqlite:///:memory:'}


def configure_db():
    """
    Establish the database, create an engine if needed, and
    register the models.

    :param conf: Mapping of configuration options
    """

    global _ENGINE, sa_logger, logger
    if not _ENGINE:
        timeout = db_opts['sql_idle_timeout']
        sql_connection = db_opts['sql_connection']
        try:
            _ENGINE = create_engine(sql_connection, pool_recycle=timeout)
        except Exception:
            msg = _("Error configuring registry database with supplied "
                    "sql_connection '%(sql_connection)s'. "
                    "Got error:\n%(err)s") % locals()
            logger.error(msg)
            raise

        sa_logger = logging.getLogger('sqlalchemy.engine')
        sa_logger.setLevel(logging.DEBUG)

        models.register_models(_ENGINE)


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
    global _MAKER, _ENGINE
    if not _MAKER:
        assert _ENGINE
        _MAKER = sessionmaker(bind=_ENGINE,
                              autocommit=autocommit,
                              expire_on_commit=expire_on_commit)
    return _MAKER()


def create_account(account, type):
    """
    creates a new account with the given identifier and type

    :param account: the account identifier
    :param type: the type of the account (user, group, atlas)
    """

    session = get_session()
    with session.begin():

        values = {}
        values['account'] = account
        values['type'] = type

        new_account = models.Account()

        new_account.update(values)

        try:
            new_account.save(session=session)
        except IntegrityError:
            raise exception.Duplicate('Account ID %s already exists!' % values['account'])

    return 0


def list_accounts():
    """
    Returns a list of all accounts
    """

    session = get_session()
    account_list = []

    with session.begin():
        for account in session.query(models.Account).order_by(models.Account.account):
            account_list.append(account)

    return account_list


def get_account(account):
    """
    Returns a single account

    :param account: The id of the account
    """

    session = get_session()

    result = None
    with session.begin():
        result = session.query(models.Account).filter_by(account=account).first()

    if result is None:
        raise exception.NotFound('Account with ID %s cannot be found' % account)
    return result


def create_subscription(account):
    """
    creates a new subscription

    :param account: the account identifier
    """
    session = get_session()
    with session.begin():

        values = {}
        values['account'] = account

        new_subscription = models.Account()

        new_subscription.update(values)

        new_subscription.save(session=session)

    return 0
