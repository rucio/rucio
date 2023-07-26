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

from typing import TYPE_CHECKING

import rucio.core.scope
from rucio.common.config import config_get
from rucio.common.types import InternalScope, InternalAccount
from rucio.core.account import has_account_attribute, list_account_attributes
from rucio.core.did import get_metadata
from rucio.core.identity import exist_identity_account
from rucio.core.lifetime_exception import list_exceptions
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rule
from rucio.db.sqla.constants import IdentityType

if TYPE_CHECKING:
    from typing import Optional
    from sqlalchemy.orm import Session


def has_permission(issuer: "InternalAccount", action: str, kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer: Account identifier which issues the command..
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    perm = {'add_account': perm_add_account,
            'del_account': perm_del_account,
            'update_account': perm_update_account,
            'add_rule': perm_add_rule,
            'add_subscription': perm_add_subscription,
            'add_scope': perm_add_scope,
            'add_rse': perm_add_rse,
            'update_rse': perm_update_rse,
            'add_protocol': perm_add_protocol,
            'del_protocol': perm_del_protocol,
            'update_protocol': perm_update_protocol,
            'declare_bad_file_replicas': perm_declare_bad_file_replicas,
            'declare_suspicious_file_replicas': perm_declare_suspicious_file_replicas,
            'add_replicas': perm_add_replicas,
            'delete_replicas': perm_delete_replicas,
            'skip_availability_check': perm_skip_availability_check,
            'update_replicas_states': perm_update_replicas_states,
            'add_rse_attribute': perm_add_rse_attribute,
            'del_rse_attribute': perm_del_rse_attribute,
            'del_rse': perm_del_rse,
            'del_rule': perm_del_rule,
            'update_rule': perm_update_rule,
            'approve_rule': perm_approve_rule,
            'update_subscription': perm_update_subscription,
            'reduce_rule': perm_reduce_rule,
            'move_rule': perm_move_rule,
            'get_auth_token_user_pass': perm_get_auth_token_user_pass,
            'get_auth_token_gss': perm_get_auth_token_gss,
            'get_auth_token_x509': perm_get_auth_token_x509,
            'get_auth_token_saml': perm_get_auth_token_saml,
            'add_account_identity': perm_add_account_identity,
            'add_did': perm_add_did,
            'add_dids': perm_add_dids,
            'attach_dids': perm_attach_dids,
            'detach_dids': perm_detach_dids,
            'attach_dids_to_dids': perm_attach_dids_to_dids,
            'create_did_sample': perm_create_did_sample,
            'set_metadata': perm_set_metadata,
            'set_metadata_bulk': perm_set_metadata_bulk,
            'set_status': perm_set_status,
            'queue_requests': perm_queue_requests,
            'set_rse_usage': perm_set_rse_usage,
            'set_rse_limits': perm_set_rse_limits,
            'get_request_by_did': perm_get_request_by_did,
            'cancel_request': perm_cancel_request,
            'get_next': perm_get_next,
            'set_local_account_limit': perm_set_local_account_limit,
            'set_global_account_limit': perm_set_global_account_limit,
            'delete_local_account_limit': perm_delete_local_account_limit,
            'delete_global_account_limit': perm_delete_global_account_limit,
            'config_sections': perm_config,
            'config_add_section': perm_config,
            'config_has_section': perm_config,
            'config_options': perm_config,
            'config_has_option': perm_config,
            'config_get': perm_config,
            'config_items': perm_config,
            'config_set': perm_config,
            'config_remove_section': perm_config,
            'config_remove_option': perm_config,
            'get_local_account_usage': perm_get_local_account_usage,
            'get_global_account_usage': perm_get_global_account_usage,
            'add_attribute': perm_add_account_attribute,
            'del_attribute': perm_del_account_attribute,
            'list_heartbeats': perm_list_heartbeats,
            'resurrect': perm_resurrect,
            'update_lifetime_exceptions': perm_update_lifetime_exceptions,
            'get_auth_token_ssh': perm_get_auth_token_ssh,
            'get_signed_url': perm_get_signed_url,
            'add_bad_pfns': perm_add_bad_pfns,
            'del_account_identity': perm_del_account_identity,
            'del_identity': perm_del_identity,
            'remove_did_from_followed': perm_remove_did_from_followed,
            'remove_dids_from_followed': perm_remove_dids_from_followed}

    return perm.get(action, perm_default)(issuer=issuer, kwargs=kwargs, session=session)


def _is_root(issuer):
    return issuer.external == 'root'


def _perm_country(issuer: "InternalAccount", rses: list, roles: list, *, session: "Optional[Session]" = None) -> bool:
    admin_in_country = []
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])
    if admin_in_country:
        for rse in rses:
            if list_rse_attributes(rse_id=rse['id'], session=session).get('country') in admin_in_country:
                return True
    return False


def perm_default(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Default permission.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or has_account_attribute(account=issuer, key='admin', session=session)


def perm_add_rse(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_update_rse(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can update a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_add_rule(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    restricted_scopes = config_get('permission', 'restricted_scopes', raise_exception=False, default=[], session=session)
    # TODO change to config_get_list
    if kwargs['account'] == issuer:
        if kwargs.get('scope') and restricted_scopes and kwargs['scope'] in restricted_scopes:
            return False
        if kwargs.get('dids'):
            for did in kwargs['dids']:
                if restricted_scopes and did['scope'] in restricted_scopes:
                    return False
        return True
    return perm_default(issuer, kwargs, session=session) or has_account_attribute(account=issuer, key='rule_admin', session=session)


def perm_add_subscription(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add a subscription.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='subscription_admin', session=session)


def perm_add_rse_attribute(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add a RSE attribute.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_del_rse_attribute(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete a RSE attribute.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_del_rse(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_add_account(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_del_account(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can del an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_update_account(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can update an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_add_scope(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add a scope to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='scope_admin', session=session)


def perm_get_auth_token_user_pass(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['username'], type_=IdentityType.USERPASS, account=kwargs['account'], session=session):
        return True
    return False


def perm_get_auth_token_gss(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['gsscred'], type_=IdentityType.GSS, account=kwargs['account'], session=session):
        return True
    return False


def perm_get_auth_token_x509(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['dn'], type_=IdentityType.X509, account=kwargs['account'], session=session):
        return True
    return False


def perm_get_auth_token_saml(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['saml_nameid'], type_=IdentityType.SAML, account=kwargs['account'], session=session):
        return True
    return False


def perm_add_account_identity(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_del_account_identity(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_del_identity(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete an identity.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_add_did(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add an data identifier to a scope.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    # Check the accounts of the issued rules
    for rule in kwargs.get('rules', []):
        kwargs_rule = rule
        if 'scope' not in kwargs_rule:
            if kwargs['scope'] and not isinstance(kwargs['scope'], str):
                kwargs_rule['scope'] = kwargs['scope'].external
            else:
                kwargs_rule['scope'] = kwargs['scope']
        if not perm_add_rule(issuer, kwargs=kwargs_rule, session=session):
            return False

    scope = kwargs['scope']
    if isinstance(kwargs['scope'], str):
        scope = InternalScope(kwargs['scope'])
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or has_account_attribute(account=issuer, key='production_account', session=session)\
        or rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)\
        or (kwargs.get('name', False) and kwargs['name'].startswith('/belle/scout'))


def perm_add_dids(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can bulk add data identifiers.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    # Check the accounts of the issued rules
    for did in kwargs['dids']:
        if not perm_add_did(issuer, kwargs=did, session=session):
            return False
    return True


def perm_attach_dids(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can append an data identifier to the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_attach_dids_to_dids(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can append an data identifier to the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if perm_default(issuer, kwargs, session=session) or has_account_attribute(account=issuer, key='did_admin', session=session):
        return True
    else:
        attachments = kwargs['attachments']
        scopes = [did['scope'] for did in attachments]
        scopes = list(set(scopes))
        for scope in scopes:
            if not rucio.core.scope.is_scope_owner(scope, issuer, session=session):
                return False
        return True


def perm_create_did_sample(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can create a sample of a data identifier collection.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'


def perm_del_rule(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an issuer can delete a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    rule = get_rule(rule_id=kwargs['rule_id'], session=session)
    rses = parse_expression(rule['rse_expression'], filter_={'vo': issuer.vo}, session=session)
    # Check if user is a country admin
    if _perm_country(issuer=issuer, rses=rses, roles=['admin', ], session=session):
        return True

    # DELETERS can delete the rule
    for rse in rses:
        rse_attr = list_rse_attributes(rse_id=rse['id'], session=session)
        if rse_attr.get('rule_deleters'):
            if issuer.external in rse_attr.get('rule_deleters').split(','):
                return True
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rule_admin', session=session)\
        or get_rule(kwargs['rule_id'], session=session)['account'] == issuer


def perm_update_rule(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an issuer can update a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rule_admin', session=session)\
        or (kwargs.get('rule_id', False) and get_rule(kwargs['rule_id'], session=session)['account'] == issuer)


def perm_approve_rule(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an issuer can approve a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rule_admin', session=session)


def perm_reduce_rule(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an issuer can reduce a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rule_admin', session=session)


def perm_move_rule(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an issuer can move a replication rule.

    :param issuer:   Account identifier which issues the command.
    :param kwargs:   List of arguments for the action.
    :param session: The DB session to use
    :returns:        True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rule_admin', session=session)\
        or get_rule(kwargs['rule_id'], session=session)['account'] == issuer


def perm_update_subscription(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can update a subscription.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='subscription_admin', session=session)


def perm_detach_dids(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can detach an data identifier from the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_set_metadata_bulk(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    meta = get_metadata(kwargs['scope'], kwargs['name'], session=session)
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or meta.get('account', '') == issuer\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_set_metadata(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    meta = get_metadata(kwargs['scope'], kwargs['name'], session=session)
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or meta.get('account', '') == issuer\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_set_status(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set status on an data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    meta = get_metadata(kwargs['scope'], kwargs['name'], session=session)
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='did_admin', session=session)\
        or meta.get('account', '') == issuer\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_add_protocol(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add a protocol to an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_del_protocol(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete protocols from an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_update_protocol(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can update protocols of an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_declare_bad_file_replicas(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can declare bad file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)


def perm_declare_suspicious_file_replicas(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can declare suspicious file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_add_replicas(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    rses = [{'id': kwargs['rse_id']}]
    if str(kwargs.get('rse', '')).endswith('LOCAL-SE')\
            and _perm_country(issuer=issuer, rses=rses, roles=['admin', 'user'], session=session):
        return True
    return str(kwargs.get('rse', '')).endswith('TMP-SE')\
        or perm_default(issuer, kwargs, session=session)


def perm_skip_availability_check(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can skip the availabity check to add/delete file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)


def perm_delete_replicas(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return False


def perm_update_replicas_states(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)


def perm_queue_requests(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can submit transfer or deletion requests on destination RSEs for data identifiers.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_query_request(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can query a request.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_get_request_by_did(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can get a request by DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_cancel_request(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can cancel a request.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_get_next(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can retrieve the next request matching the request type and state.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_set_rse_usage(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set RSE usage information.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_set_rse_limits(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set RSE limits.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)


def perm_set_local_account_limit(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set an account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    rses = [{'id': kwargs['rse_id']}]
    if _perm_country(issuer=issuer, rses=rses, roles=['admin', ], session=session):
        return True
    return perm_default(issuer, kwargs, session=session)\
        or (has_account_attribute(account=issuer, key='rse_admin', session=session) and has_account_attribute(account=issuer, key='account_admin', session=session))


def perm_set_global_account_limit(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can set a global account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or (has_account_attribute(account=issuer, key='rse_admin', session=session) and has_account_attribute(account=issuer, key='account_admin', session=session))


def perm_delete_local_account_limit(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete an account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or (has_account_attribute(account=issuer, key='rse_admin', session=session) and has_account_attribute(account=issuer, key='account_admin', session=session))


def perm_delete_global_account_limit(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can delete a global account limit.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or (has_account_attribute(account=issuer, key='rse_admin', session=session) and has_account_attribute(account=issuer, key='account_admin', session=session))


def perm_config(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can read/write the configuration.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='config_admin', session=session)


def perm_get_local_account_usage(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can get the account usage of an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or kwargs.get('account') == issuer\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_get_global_account_usage(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can get the account usage of an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or kwargs.get('account') == issuer\
        or has_account_attribute(account=issuer, key='rse_admin', session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_add_account_attribute(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add attributes to accounts.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_del_account_attribute(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can add attributes to accounts.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='account_admin', session=session)


def perm_list_heartbeats(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can list heartbeats.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)


def perm_resurrect(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can resurrect DIDS.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)


def perm_update_lifetime_exceptions(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can approve/reject Lifetime Model exceptions.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if kwargs['vo'] is not None:
        exceptions = next(list_exceptions(exception_id=kwargs['exception_id'], states=False, session=session))
        if exceptions['scope'].vo != kwargs['vo']:
            return False
    return perm_default(issuer, kwargs, session=session)


def perm_get_auth_token_ssh(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can request an ssh token.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return True


def perm_get_signed_url(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can request a signed URL.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or has_account_attribute(account=issuer, key='sign-gcs', session=session)


def perm_add_bad_pfns(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can declare bad PFNs.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)


def perm_remove_did_from_followed(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can remove did from followed table.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or kwargs['account'] == issuer


def perm_remove_dids_from_followed(issuer: "InternalAccount", kwargs: dict, *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account can bulk remove dids from followed table.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_default(issuer, kwargs, session=session)\
        or kwargs['account'] == issuer
