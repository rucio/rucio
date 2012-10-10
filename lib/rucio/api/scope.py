# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from rucio.core import scope


def list_scopes():
    """
    Lists all scopes.

    :returns: A list containing all scopes.
    """
    return scope.list_scopes()


def add_scope(scopeName, accountName):
    """
    Creates a scope for an account.

    :param accountName: The account name.
    :param scopeName: The scope identifier.
    """
    scope.add_scope(scopeName, accountName)


def get_scopes(accountName):
    """
    Gets a list of all scopes for an account.

    :param accountName: The account name.

    :returns: A list containing the names of all scopes for this account.
    """
    return scope.get_scopes(accountName)
