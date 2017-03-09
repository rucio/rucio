# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Tomas Kouba, <tomas.kouba@cern.ch>, 2014
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

"""
Interface for identity abstraction layer
"""


from rucio.api import permission
from rucio.common import exception
from rucio.core import identity
from rucio.db.sqla.constants import IdentityType


def add_identity(identity_key, id_type, email, password=None):
    """
    Creates a user identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass)
    :param email: The Email address associated with the identity.
    :param password: If type==userpass, this sets the password.
    """
    return identity.add_identity(identity_key, IdentityType.from_sym(id_type), email, password=password)


def del_identity(identity_key, id_type):
    """
    Deletes a user identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass).
    """
    return identity.del_identity(identity_key, IdentityType.from_sym(id_type))


def add_account_identity(identity_key, id_type, account, email, issuer, default=False):
    """
    Adds a membership association between identity and account.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param email: The Email address associated with the identity.
    :param issuer: The issuer account.
    :param default: If True, the account should be used by default with the provided identity.
    """
    kwargs = {'identity': identity_key, 'type': id_type, 'account': account}
    if not permission.has_permission(issuer=issuer, action='add_account_identity', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add account identity' % (issuer))

    return identity.add_account_identity(identity=identity_key, type=IdentityType.from_sym(id_type), default=default, email=email, account=account)


def del_account_identity(identity_key, id_type, account):
    """
    Removes a membership association between identity and account.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    """
    return identity.del_account_identity(identity_key, IdentityType.from_sym(id_type), account)


def list_identities(**kwargs):
    """
    Returns a list of all enabled identities.

    returns: A list of all enabled identities.
    """
    return identity.list_identities(**kwargs)


def get_default_account(identity_key, id_type):
    """
    Returns the default account for this identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass).
    """
    return identity.get_default_account(identity_key, IdentityType.from_sym(id_type))


def list_accounts_for_identity(identity_key, id_type):
    """
    Returns a list of all accounts for an identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass).

    returns: A list of all accounts for the identity.
    """
    return identity.list_accounts_for_identity(identity_key, IdentityType.from_sym(id_type))
