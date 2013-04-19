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
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import exc

from rucio.common import exception
from rucio.db import models
from rucio.db.session import read_session, transactional_session
from rucio.db.constants import AccountStatus


@transactional_session
def add_account(account, type, session=None):
    """ Add an account with the given account name and type.

    :param account: the name of the new account.
    :param type: the type of the new account.
    :param session: the database session in use.
    """
    new_account = models.Account(account=account, type=type, status=AccountStatus.ACTIVE)
    try:
        new_account.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('Account ID \'%s\' already exists!' % account)


@read_session
def account_exists(account, session=None):
    """ Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account.
    :param session: the database session in use.

    :returns: True if found, otherwise false.
    """

    query = session.query(models.Account).filter_by(account=account)

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


@read_session
def get_account_status(account, session=None):
    """ Returns the state of the account.

    :param account: Name of the account.
    :param session: the database session in use.

    """

    query = session.query(models.Account).filter_by(account=account)

    acc_details = query.one()
    return acc_details.status


@transactional_session
def set_account_status(account, status, session=None):
    """ Set the status of an account.

    :param account: Name of the account.
    :param status: The status for the account.
    :param session: the database session in use.
    """
    session.query(models.Account).filter_by(account=account).update({'status': status})


@read_session
def list_accounts(session=None):
    """ Returns a list of all account names.

    :param session: the database session in use.

    returns: a list of all account names.
    """

    query = session.query(models.Account).filter_by(status=AccountStatus.ACTIVE)
    for row in query.order_by(models.Account.account).yield_per(25):
        yield {'account': row.account, 'type': row.type}


@read_session
def list_identities(account, session=None):
    """
    List all identities on an account.

    :param account: The account name.
    :param session: the database session in use.
    """
    identity_list = list()

    query = session.query(models.Account).filter_by(account=account).filter_by(deleted=False)

    try:
        query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account)

    query = session.query(models.IdentityAccountAssociation).filter_by(account=account)
    for identity in query:
        identity_list.append({'type': identity.type, 'identity': identity.identity})

    return identity_list
