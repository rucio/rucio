# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import rucio.api.permission
import rucio.common.exception

from rucio.core import scope as core_scope
from rucio.common.schema import validate_schema


def list_scopes():
    """
    Lists all scopes.

    :returns: A list containing all scopes.
    """
    return core_scope.list_scopes()


def add_scope(scope, account, issuer):
    """
    Creates a scope for an account.

    :param account: The account name.
    :param scope: The scope identifier.
    :param issuer: The issuer account.
    """

    validate_schema(name='scope', obj=scope)

    kwargs = {'scope': scope, 'account': account}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_scope', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add scope' % (issuer))

    core_scope.add_scope(scope, account)


def get_scopes(account):
    """
    Gets a list of all scopes for an account.

    :param account: The account name.

    :returns: A list containing the names of all scopes for this account.
    """
    return core_scope.get_scopes(account)
