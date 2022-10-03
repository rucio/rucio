# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

"""
Interface for identity abstraction layer
"""

import typing
from rucio.api import permission
from rucio.common import exception
from rucio.common.types import InternalAccount
from rucio.core import identity
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_identity(identity_key, id_type, email, password=None, session=None):
    """
    Creates a user identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml)
    :param email: The Email address associated with the identity.
    :param password: If type==userpass, this sets the password.
    :param session: The database session in use.
    """
    return identity.add_identity(identity_key, IdentityType[id_type.upper()], email, password=password, session=session)


@transactional_session
def del_identity(identity_key, id_type, issuer, vo='def', session=None):
    """
    Deletes a user identity.
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param issuer: The issuer account.
    :param vo: the VO of the issuer.
    :param session: The database session in use.
    """
    id_type = IdentityType[id_type.upper()]
    kwargs = {'accounts': identity.list_accounts_for_identity(identity_key, id_type, session=session)}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_identity', kwargs=kwargs, session=session):
        raise exception.AccessDenied('Account %s can not delete identity' % (issuer))

    return identity.del_identity(identity_key, id_type, session=session)


@transactional_session
def add_account_identity(identity_key, id_type, account, email, issuer, default=False, password=None, vo='def', session=None):
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
    :param session: The database session in use.
    """
    kwargs = {'identity': identity_key, 'type': id_type, 'account': account}
    if not permission.has_permission(issuer=issuer, vo=vo, action='add_account_identity', kwargs=kwargs, session=session):
        raise exception.AccessDenied('Account %s can not add account identity' % (issuer))

    account = InternalAccount(account, vo=vo)

    return identity.add_account_identity(identity=identity_key, type_=IdentityType[id_type.upper()], default=default,
                                         email=email, account=account, password=password, session=session)


@read_session
def verify_identity(identity_key: str, id_type: str, password: typing.Union[str, None] = None, session=None) -> bool:
    """
    Verifies a user identity.
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml)
    :param password: If type==userpass, verifies the identity_key, .
    :param session: The database session in use.
    """
    return identity.verify_identity(identity_key, IdentityType[id_type.upper()], password=password, session=session)


@transactional_session
def del_account_identity(identity_key, id_type, account, issuer, vo='def', session=None):
    """
    Removes a membership association between identity and account.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: the VO to act on.
    :param session: The database session in use.
    """
    kwargs = {'account': account}
    if not permission.has_permission(issuer=issuer, vo=vo, action='del_account_identity', kwargs=kwargs, session=session):
        raise exception.AccessDenied('Account %s can not delete account identity' % (issuer))

    account = InternalAccount(account, vo=vo)

    return identity.del_account_identity(identity_key, IdentityType[id_type.upper()], account, session=session)


@read_session
def list_identities(session=None, **kwargs):
    """
    Returns a list of all enabled identities.

    :param session: The database session in use.
    returns: A list of all enabled identities.
    """
    return identity.list_identities(session=session, **kwargs)


@read_session
def get_default_account(identity_key, id_type, session=None):
    """
    Returns the default account for this identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param session: The database session in use.
    """
    account = identity.get_default_account(identity_key, IdentityType[id_type.upper()], session=session)
    return account.external


@read_session
def list_accounts_for_identity(identity_key, id_type, session=None):
    """
    Returns a list of all accounts for an identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param session: The database session in use.

    returns: A list of all accounts for the identity.
    """
    accounts = identity.list_accounts_for_identity(identity_key, IdentityType[id_type.upper()], session=session)
    return [account.external for account in accounts]
