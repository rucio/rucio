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

import logging

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import scoped_session, sessionmaker

from rucio.common import exception as r_exception
from rucio.common.config import config_get
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
        raise r_exception.AccountNotFound('Account ID \'%s\' does not exist')

    values = {}
    values['scope'] = scope
    values['account'] = account

    new_scope = models.Scope()

    new_scope.update(values)

    try:
        new_scope.save(session=session)
    except IntegrityError, e:
        session.rollback()
        raise r_exception.Duplicate('Scope \'%s\' already exists!' % values['scope'])

    session.commit()


def bulk_add_scopes(scopes, account, skipExisting=False):
    """ add a group of scopes, this call should not be exposed to users.

    :param scopes: a list of scopes to be added.
    :param account: the account associated to the scopes.
    """

    for scope in scopes:
        try:
            add_scope(scope, account)
        except r_exception.Duplicate, error:
            if skipExisting:
                pass
            else:
                raise


def get_scopes(account):
    """ get all scopes defined for an account.

    :param account: the account name to list the scopes of.
    :returns: a list of all scope names for this account.
    """

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
