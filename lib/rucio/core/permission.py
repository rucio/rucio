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

import rucio.core.authentication


def has_permission(issuer, action, kwargs):
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer: Account identifier which issues the command..
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    perm = {'add_account': perm_add_account,
            'add_scope': perm_add_scope,
            'add_rse': perm_add_rse,
            'add_rse_attr': perm_add_rse_attr,
            'del_rse_attr': perm_del_rse_attr,
            'del_rse': perm_del_rse,
            'get_auth_token_user_pass': perm_get_auth_token_user_pass,
            'get_auth_token_gss': perm_get_auth_token_gss,
            'get_auth_token_x509': perm_get_auth_token_x509,
            'add_account_identity': perm_add_account_identity, }

    return perm.get(action, perm_default)(issuer=issuer, kwargs=kwargs)


def perm_default(issuer, kwargs):
    """
    Default permission.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return True


def perm_add_rse(issuer, kwargs):
    """
    Checks if an account can add a RSE.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_add_rse_attr(issuer, kwargs):
    """
    Checks if an account can add a RSE attribute.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_del_rse_attr(issuer, kwargs):
    """
    Checks if an account can delete a RSE attribute.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_del_rse(issuer, kwargs):
    """
    Checks if an account can delete a RSE.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_add_account(issuer, kwargs):
    """
    Checks if an account can add an account.

    :param accountName: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_add_scope(issuer, kwargs):
    """
    Checks if an account can add a scop to a account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or issuer == kwargs.get('accountName')


def perm_get_auth_token_user_pass(issuer, kwargs):
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if rucio.core.authentication.exist_identity_account(identity=kwargs['username'], type='userpass', account=kwargs['account']):
        return True
    return False


def perm_get_auth_token_gss(issuer, kwargs):
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if rucio.core.authentication.exist_identity_account(identity=kwargs['gsscred'], type='gss', account=kwargs['account']):
        return True
    return False


def perm_get_auth_token_x509(issuer, kwargs):
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if rucio.core.authentication.exist_identity_account(identity=kwargs['dn'], type='x509', account=kwargs['account']):
        return True
    return False


def perm_add_account_identity(issuer, kwargs):
    """
    Checks if an account can add an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or issuer == kwargs.get('accountName')
