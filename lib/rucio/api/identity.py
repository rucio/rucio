# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import rucio.core.identity


def add_identity(identity, type, password=None):
    """
    Creates a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass)
    :param password: If type==userpass, this sets the password.
    """
    rucio.core.identity.add_identity(identity, type, password)


def del_identity(identity, type):
    """
    Deletes a user identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    """
    rucio.core.identity.del_identity(identity, type)


def add_account_identity(identity, type, account, default=False):
    """
    Adds a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    :param default: If True, the account should be used by default with the provided identity.
    """
    rucio.core.identity.add_account_member(identity, type, account, default)


def del_account_identity(identity, type, account):
    """
    Removes a membership association between identity and account.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param type: The type of the authentication (x509, gss, userpass).
    :param account: The account name.
    """
    rucio.core.identity.del_account_member(identity, type, account)


def list_identities(**kwargs):
    """
    Returns a list of all enabled identities.

    returns: A list of all enabled identities.
    """
    rucio.core.identity.list_identities(**kwargs)
