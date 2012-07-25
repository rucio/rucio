# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2011
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011


def has_permission(accountName, action, kwargs):
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param accountName: Account identifier.
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    perm = {'add_account': perm_add_account,
            'add_scope': perm_add_scope,
           }

    return perm.get(action, perm_default)(accountName=accountName, kwargs=kwargs)


def perm_default(accountName, kwargs):
    """
    Default permission.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return True


def perm_add_account(accountName, kwargs):
    """
    Checks if an account can add an account.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if accountName == 'root':
        return True
    return False


def perm_add_scope(accountName, kwargs):
    """
    Checks if an account can add a scop to a account.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """

    if accountName == 'root':
        return True

    if accountName == kwargs.get('accountName'):
        return True

    return False
