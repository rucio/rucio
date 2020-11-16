# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Tomáš Kouba <tomas.kouba@cern.ch>, 2014
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019

"""
Interface for identity abstraction layer
"""

from rucio.api import permission
from rucio.common import exception
from rucio.common.types import InternalAccount
from rucio.core import identity
from rucio.db.sqla.constants import IdentityType


def add_identity(identity_key, id_type, email, password=None):
    """
    Creates a user identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml)
    :param email: The Email address associated with the identity.
    :param password: If type==userpass, this sets the password.
    """
    return identity.add_identity(identity_key, IdentityType[id_type.upper()], email, password=password)


def del_identity(identity_key, id_type, issuer, vo='def'):
    """
    Deletes a user identity.
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param issuer: The issuer account.
    :param vo: the VO of the issuer.
    """
    id_type = IdentityType[id_type.upper()]
    kwargs = {'accounts': identity.list_accounts_for_identity(identity_key, id_type)}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_identity', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete identity' % (issuer))

    return identity.del_identity(identity_key, id_type)


def add_account_identity(identity_key, id_type, account, email, issuer, default=False, password=None, vo='def'):
    """
    Adds a membership association between identity and account.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param account: The account name.
    :param email: The Email address associated with the identity.
    :param issuer: The issuer account.
    :param default: If True, the account should be used by default with the provided identity.
    :param password: Password if id_type is userpass.
    :param vo: the VO to act on.
    """
    kwargs = {'identity': identity_key, 'type': id_type, 'account': account}
    if not permission.has_permission(issuer=issuer, vo=vo, action='add_account_identity', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not add account identity' % (issuer))

    account = InternalAccount(account, vo=vo)

    return identity.add_account_identity(identity=identity_key, type=IdentityType[id_type.upper()], default=default, email=email, account=account, password=password)


def del_account_identity(identity_key, id_type, account, issuer, vo='def'):
    """
    Removes a membership association between identity and account.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: the VO to act on.
    """
    kwargs = {'account': account}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_account_identity', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not delete account identity' % (issuer))

    account = InternalAccount(account, vo=vo)

    return identity.del_account_identity(identity_key, IdentityType[id_type.upper()], account)


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
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    """
    account = identity.get_default_account(identity_key, IdentityType[id_type.upper()])
    return account.external


def list_accounts_for_identity(identity_key, id_type):
    """
    Returns a list of all accounts for an identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).

    returns: A list of all accounts for the identity.
    """
    accounts = identity.list_accounts_for_identity(identity_key, IdentityType[id_type.upper()])
    return [account.external for account in accounts]
