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

from sqlalchemy.exc import IntegrityError

from rucio.common.exception import AccountNotFound, Duplicate, RucioException
from rucio.db import models1 as models
from rucio.db.session import get_session

session = get_session()


def add_scope(scope, account):
    """ add a scope for the given account name.

    :param scope: the name for the new scope.
    :param account: the account to add the scope to.
    """

    result = session.query(models.Account).filter_by(account=account).first()

    if result is None:
        raise AccountNotFound('Account ID \'%s\' does not exist' % account)

    values = {}
    values['scope'] = scope
    values['account'] = account

    new_scope = models.Scope()

    new_scope.update(values)

    try:
        new_scope.save(session=session)
    except IntegrityError, e:
        session.rollback()
        if e.args[0] == "(IntegrityError) column scope is not unique":
            raise Duplicate('Scope \'%s\' already exists!' % values['scope'])
        else:
            raise RucioException(e.args[0])

    session.commit()


def bulk_add_scopes(scopes, account, skipExisting=False):
    """ add a group of scopes, this call should not be exposed to users.

    :param scopes: a list of scopes to be added.
    :param account: the account associated to the scopes.
    """

    for scope in scopes:
        try:
            add_scope(scope, account)
        except Duplicate:
            if skipExisting:
                pass
            else:
                raise


def list_scopes():
    """
    Lists all scopes.

    :returns: A list containing all scopes.
    """
    scope_list = []
    query = session.query(models.Scope)
    for s in query:
        scope_list.append(s.scope)
    return scope_list


def get_scopes(account):
    """ get all scopes defined for an account.

    :param account: the account name to list the scopes of.
    :returns: a list of all scope names for this account.
    """

    result = session.query(models.Account).filter_by(account=account).first()

    if result is None:
        raise AccountNotFound('Account ID \'%s\' does not exist' % account)

    scope_list = []

    for s in session.query(models.Scope).filter_by(account=account):
        scope_list.append(s.scope)

    return scope_list


def check_scope(scope_to_check):
    """ check to see if scope exists.

    :param scope: the scope to check
    :returns: True or false
    """

    return True if session.query(models.Scope).filter_by(scope=scope_to_check).first() else False
