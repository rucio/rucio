# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from rucio.core import scope


def list_scopes():
    """
    Lists all scopes.

    :returns: A list containing all scopes.
    """
    return scope.list_scopes()


def add_scope(scope_name, account):
    """
    Creates a scope for an account.

    :param account: The account name.
    :param scope: The scope identifier.
    """
    scope.add_scope(scope_name, account)


def get_scopes(account):
    """
    Gets a list of all scopes for an account.

    :param account: The account name.

    :returns: A list containing the names of all scopes for this account.
    """
    return scope.get_scopes(account)
