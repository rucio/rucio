# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import rucio.api.permission
import rucio.common.exception
import rucio.core.identity


def add_identity(identity, type, password=None):
    """
    Creates a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass)
    :param password: If type==userpass, this sets the password.
    """
    return rucio.core.identity.add_identity(identity, type, password)


def del_identity(identity, type):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    """
    return rucio.core.identity.del_identity(identity, type)


def add_account_identity(identity, type, account, issuer, default=False):
    """
    Adds a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param issuer: The issuer account.
    :param default: If True, the account should be used by default with the provided identity.
    """
    kwargs = {'identity': identity, 'type': type, 'account': account}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_account_identity', kwargs=kwargs):
            raise rucio.common.exception.AccessDenied('Account %s can not identity' % (issuer))

    return rucio.core.identity.add_account_identity(identity, type, account, default)


def del_account_identity(identity, type, account):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    """
    return rucio.core.identity.del_account_identity(identity, type, account)


def list_identities(**kwargs):
    """
    Returns a list of all enabled identities.

    returns: A list of all enabled identities.
    """
    return rucio.core.identity.list_identities(**kwargs)
