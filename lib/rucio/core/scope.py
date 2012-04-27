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

import logging

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import scoped_session, sessionmaker

from rucio.common import exception as r_exception
from rucio.common.config import config_get
from rucio.db import models1 as models

""" Only for testing """
engine = create_engine(config_get('database', 'default'))
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again

session = sessionmaker(bind=engine, autocommit=True, expire_on_commit=False)


def get_session():
    return scoped_session(session)


def add_scope(scope, account):
    """ add a scope for the given account name.

    :param scope: the name for the new scope.
    :param account: the account to add the scope to.
    """
    session = get_session()

    with session.begin():
        result = session.query(models.Account).filter_by(account=account).first()

        if result is None:
            raise r_exception.NotFound('Account ID \'%s\' does not exist')

        values = {}
        values['scope'] = scope
        values['account'] = account

        new_scope = models.Scope()

        new_scope.update(values)

        try:
            new_scope.save(session=session)
        except IntegrityError, e:
            raise r_exception.Duplicate('Scope \'%s\' already exists!' % values['scope'])
        finally:
            session.flush()


def get_scopes(account):
    """ get all scopes defined for an account.

    :param account: the account name to list the scopes of.
    :returns: a list of all scope names for this account.
    """
    session = get_session()
    scope_list = []

    with session.begin():
        for s in session.query(models.Scope).filter_by(account=account):
            scope_list.append(s.scope)

    return scope_list


def check_scope(scope_to_check):
    """ check to see if scope exists.

    :param scope: the scope to check
    :returns: True or false
    """

    session = get_session()
    if session.query(models.Scope).filter_by(scope=scope_to_check).first():
        return True
    else:
        return False
