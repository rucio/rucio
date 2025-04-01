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

from typing import TYPE_CHECKING, Optional

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO
from rucio.common.types import InternalAccount
from rucio.core import identity
from rucio.db.sqla.constants import DatabaseOperationType, IdentityType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy import Row


def add_identity(
    identity_key: str,
    id_type: str,
    email: str,
    password: Optional[str] = None,
) -> None:
    """
    Creates a user identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml)
    :param email: The Email address associated with the identity.
    :param password: If type==userpass, this sets the password.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        return identity.add_identity(identity_key, IdentityType[id_type.upper()], email, password=password, session=session)


def del_identity(
    identity_key: str,
    id_type: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Deletes a user identity.
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param issuer: The issuer account.
    :param vo: the VO of the issuer.
    """
    converted_id_type = IdentityType[id_type.upper()]

    with db_session(DatabaseOperationType.WRITE) as session:
        kwargs = {'accounts': identity.list_accounts_for_identity(identity_key, converted_id_type, session=session)}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='del_identity', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not delete identity. %s' % (issuer, auth_result.message))

        return identity.del_identity(identity_key, converted_id_type, session=session)


def add_account_identity(
    identity_key: str,
    id_type: str,
    account: str,
    email: str,
    issuer: str,
    default: bool = False,
    password: Optional[str] = None,
    vo: str = DEFAULT_VO,
) -> None:
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

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='add_account_identity', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not add account identity. %s' % (issuer, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        return identity.add_account_identity(identity=identity_key, type_=IdentityType[id_type.upper()], default=default,
                                             email=email, account=internal_account, password=password, session=session)


def verify_identity(identity_key: str, id_type: str, password: Optional[str] = None) -> bool:
    """
    Verifies a user identity.
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml)
    :param password: If type==userpass, verifies the identity_key, .
    """
    with db_session(DatabaseOperationType.READ) as session:
        return identity.verify_identity(identity_key, IdentityType[id_type.upper()], password=password, session=session)


def del_account_identity(
    identity_key: str,
    id_type: str,
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Removes a membership association between identity and account.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: the VO to act on.
    """
    kwargs = {'account': account}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='del_account_identity', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not delete account identity. %s' % (issuer, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        return identity.del_account_identity(identity_key, IdentityType[id_type.upper()], internal_account, session=session)


def list_identities(**kwargs) -> "Sequence[Row[tuple[str, IdentityType]]]":
    """
    Returns a list of all enabled identities.

    returns: A list of all enabled identities.
    """
    with db_session(DatabaseOperationType.READ) as session:
        return identity.list_identities(session=session, **kwargs)


def get_default_account(
    identity_key: str,
    id_type: str,
) -> str:
    """
    Returns the default account for this identity.

    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    """
    with db_session(DatabaseOperationType.READ) as session:
        account = identity.get_default_account(identity_key, IdentityType[id_type.upper()], session=session)
    return account.external


def list_accounts_for_identity(
    identity_key: str,
    id_type: str,
) -> list[str]:
    """
    Returns a list of all accounts for an identity.

    :param identity: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).

    returns: A list of all accounts for the identity.
    """
    with db_session(DatabaseOperationType.READ) as session:
        accounts = identity.list_accounts_for_identity(identity_key, IdentityType[id_type.upper()], session=session)
    return [account.external for account in accounts]
