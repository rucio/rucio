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

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import exc

from rucio.common import exception
from rucio.db import models
from rucio.db.session import read_session, transactional_session


class account_status:
    """ Enumerated type for account status """
    # As the corresponding column on the db is of type enum, no integers are used
    active = 'active'
    inactive = 'inactive'
    disabled = 'disabled'
    not_exist = 'not_exist'


@transactional_session
def add_account(account_name, account_type, session=None):
    """ Add an account with the given account name and type.

    :param account_name: the name of the new account.
    :param account_type: the type of the new account.
    :param session: the database session in use.
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


@read_session
def account_exists(account_name, session=None):
    """ Checks to see if account exists. This procedure does not check it's status.

    :param account_name: Name of the account.
    :param session: the database session in use.

    :returns: True if found, otherwise false.
    """

    query = session.query(models.Account).filter_by(account=account_name)

    return True if query.first() else False


@read_session
def get_account(account_name, session=None):
    """ Returns an account for the given account name.

    :param account_name: the name of the account.
    :param session: the database session in use.

    :returns: a dict with all information for the account.
    """

    query = session.query(models.Account).filter_by(account=account_name)

    result = query.first()
    if result is None:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account_name)
    return result


@transactional_session
def del_account(account_name, session=None):
    """ Disable an account with the given account name.

    :param account_name: the account name.
    :param session: the database session in use.
    """

    query = session.query(models.Account).filter_by(account=account_name).filter_by(deleted=False)

    try:
        account = query.one()
    except exc.NoResultFound:
        raise exception.AccountNotFound('Account with ID \'%s\' cannot be found' % account_name)

    account.delete(session=session)
    session.commit()


@read_session
def get_account_status(account_name, session=None):
    """ Returns the state of the account.

    :param account_name: Name of the account.
    :param session: the database session in use.

    """

    query = session.query(models.Account).filter_by(account=account_name)

    acc_details = query.one()
    return acc_details.status


@transactional_session
def set_account_status(account_name, status, session=None):
    """ Set the status of an account.

    :param account_name: Name of the account.
    :param status: The status for the account.
    :param session: the database session in use.
    """

    session.query(models.Account).filter_by(account=account_name).update({'status': status})
    session.commit()


@read_session
def list_accounts(session=None):
    """ Returns a list of all account names.

    :param session: the database session in use.

    returns: a list of all account names.
    """

    query = session.query(models.Account).filter_by(deleted=False)

    for row in query.order_by(models.Account.account):
        yield {'account': row.account, 'type': row.type}


@read_session
def list_identities(account_name, session=None):
    """
    List all identities on an account.

    :param account_name: The account name.
    :param session: the database session in use.
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
