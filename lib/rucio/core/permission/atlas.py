# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2016
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

import rucio.core.authentication
import rucio.core.did
import rucio.core.scope
from rucio.core.account import list_account_attributes, has_account_attribute
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rule
from rucio.db.sqla.constants import IdentityType, BadPFNStatus


def has_permission(issuer, action, kwargs):
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer: Account identifier which issues the command..
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
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
            'add_account_identity': perm_add_account_identity,
            'add_did': perm_add_did,
            'add_dids': perm_add_dids,
            'attach_dids': perm_attach_dids,
            'detach_dids': perm_detach_dids,
            'attach_dids_to_dids': perm_attach_dids_to_dids,
            'create_did_sample': perm_create_did_sample,
            'set_metadata': perm_set_metadata,
            'set_status': perm_set_status,
            'queue_requests': perm_queue_requests,
            'set_rse_usage': perm_set_rse_usage,
            'set_rse_limits': perm_set_rse_limits,
            'query_request': perm_query_request,
            'get_request_by_did': perm_get_request_by_did,
            'cancel_request': perm_cancel_request,
            'get_next': perm_get_next,
            'set_account_limit': perm_set_account_limit,
            'delete_account_limit': perm_delete_account_limit,
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
            'get_account_usage': perm_get_account_usage,
            'add_attribute': perm_add_account_attribute,
            'del_attribute': perm_del_account_attribute,
            'list_heartbeats': perm_list_heartbeats,
            'resurrect': perm_resurrect,
            'update_lifetime_exceptions': perm_update_lifetime_exceptions,
            'get_ssh_challenge_token': perm_get_ssh_challenge_token,
            'get_signed_url': perm_get_signed_url,
            'add_bad_pfns': perm_add_bad_pfns,
            'del_account_identity': perm_del_account_identity,
            'del_identity': perm_del_identity}

    return perm.get(action, perm_default)(issuer=issuer, kwargs=kwargs)


def perm_default(issuer, kwargs):
    """
    Default permission.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_add_rse(issuer, kwargs):
    """
    Checks if an account can add a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_update_rse(issuer, kwargs):
    """
    Checks if an account can update a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_add_rule(issuer, kwargs):
    """
    Checks if an account can add a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if kwargs['account'] == issuer and not kwargs['locked']:
        return True
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True

    return False


def perm_add_subscription(issuer, kwargs):
    """
    Checks if an account can add a subscription.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True

    return False


def perm_add_rse_attribute(issuer, kwargs):
    """
    Checks if an account can add a RSE attribute.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True
    if kwargs['key'] in ['rule_deleters', 'auto_approve_bytes', 'auto_approve_files', 'rule_approvers', 'default_account_limit_bytes', 'default_limit_files', 'block_manual_approve']:
        # Check if user is a country admin
        admin_in_country = []
        for kv in list_account_attributes(account=issuer):
            if kv['key'].startswith('country-') and kv['value'] == 'admin':
                admin_in_country.append(kv['key'].partition('-')[2])
        if admin_in_country:
            if list_rse_attributes(rse=kwargs['rse']).get('country') in admin_in_country:
                return True
    return False


def perm_del_rse_attribute(issuer, kwargs):
    """
    Checks if an account can delete a RSE attribute.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True
    if kwargs['key'] in ['rule_deleters', 'auto_approve_bytes', 'auto_approve_files', 'rule_approvers', 'default_account_limit_bytes', 'default_limit_files', 'block_manual_approve']:
        # Check if user is a country admin
        admin_in_country = []
        for kv in list_account_attributes(account=issuer):
            if kv['key'].startswith('country-') and kv['value'] == 'admin':
                admin_in_country.append(kv['key'].partition('-')[2])
        if admin_in_country:
            if list_rse_attributes(rse=kwargs['rse']).get('country') in admin_in_country:
                return True
    return False


def perm_del_rse(issuer, kwargs):
    """
    Checks if an account can delete a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_add_account(issuer, kwargs):
    """
    Checks if an account can add an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_del_account(issuer, kwargs):
    """
    Checks if an account can del an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_update_account(issuer, kwargs):
    """
    Checks if an account can update an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_add_scope(issuer, kwargs):
    """
    Checks if an account can add a scop to a account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or issuer == kwargs.get('account')


def perm_get_auth_token_user_pass(issuer, kwargs):
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if rucio.core.authentication.exist_identity_account(identity=kwargs['username'], type=IdentityType.USERPASS, account=kwargs['account']):
        return True
    return False


def perm_get_auth_token_gss(issuer, kwargs):
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if rucio.core.authentication.exist_identity_account(identity=kwargs['gsscred'], type=IdentityType.GSS, account=kwargs['account']):
        return True
    return False


def perm_get_auth_token_x509(issuer, kwargs):
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if rucio.core.authentication.exist_identity_account(identity=kwargs['dn'], type=IdentityType.X509, account=kwargs['account']):
        return True
    return False


def perm_add_account_identity(issuer, kwargs):
    """
    Checks if an account can add an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """

    return issuer == 'root' or issuer == kwargs.get('account')


def perm_del_account_identity(issuer, kwargs):
    """
    Checks if an account can delete an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """

    return issuer == 'root' or issuer == kwargs.get('account')


def perm_del_identity(issuer, kwargs):
    """
    Checks if an account can delete an identity.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """

    return issuer == 'root' or issuer in kwargs.get('accounts')


def perm_add_did(issuer, kwargs):
    """
    Checks if an account can add an data identifier to a scope.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    # Check the accounts of the issued rules
    if issuer != 'root' and not has_account_attribute(account=issuer, key='admin'):
        for rule in kwargs.get('rules', []):
            if rule['account'] != issuer:
                return False

    return issuer == 'root'\
        or has_account_attribute(account=issuer, key='admin')\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer)\
        or kwargs['scope'] == u'mock'


def perm_add_dids(issuer, kwargs):
    """
    Checks if an account can bulk add data identifiers.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    # Check the accounts of the issued rules
    if issuer != 'root' and not has_account_attribute(account=issuer, key='admin'):
        for did in kwargs['dids']:
            for rule in did.get('rules', []):
                if rule['account'] != issuer:
                    return False

    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_attach_dids(issuer, kwargs):
    """
    Checks if an account can append an data identifier to the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'\
        or has_account_attribute(account=issuer, key='admin')\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer)\
        or kwargs['scope'] == 'mock'


def perm_attach_dids_to_dids(issuer, kwargs):
    """
    Checks if an account can append an data identifier to the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True
    attachments = kwargs['attachments']
    scopes = [did['scope'] for did in attachments]
    scopes = list(set(scopes))
    for scope in scopes:
        if not rucio.core.scope.is_scope_owner(scope, issuer):
            return False
    return True


def perm_create_did_sample(issuer, kwargs):
    """
    Checks if an account can create a sample of a data identifier collection.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'\
        or has_account_attribute(account=issuer, key='admin')\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer)\
        or kwargs['scope'] == 'mock'


def perm_del_rule(issuer, kwargs):
    """
    Checks if an issuer can delete a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if issuer == 'root' or issuer == 'ddmadmin':
        return True
    if get_rule(kwargs['rule_id'])['account'] == issuer:
        return True

    # Check if user is a country admin
    admin_in_country = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])

    rule = get_rule(rule_id=kwargs['rule_id'])
    rses = parse_expression(rule['rse_expression'])
    if admin_in_country:
        for rse in rses:
            if list_rse_attributes(rse=None, rse_id=rse['id']).get('country') in admin_in_country:
                return True

    # DELETERS can approve the rule
    for rse in rses:
        rse_attr = list_rse_attributes(rse=None, rse_id=rse['id'])
        if rse_attr.get('rule_deleters'):
            if issuer in rse_attr.get('rule_deleters').split(','):
                return True

    return False


def perm_update_rule(issuer, kwargs):
    """
    Checks if an issuer can update a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    # Admin accounts can do everything
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True

    # Only admin accounts can change account, state, priority of a rule
    if 'account' in kwargs['options'] or\
       'state' in kwargs['options'] or\
       'priority' in kwargs['options'] or\
       'child_rule_id' in kwargs['options'] or\
       'meta' in kwargs['options']:
        return False  # Only priv accounts are allowed to change that

    # Country admins are allowed to change the rest.
    admin_in_country = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])

    rule = get_rule(rule_id=kwargs['rule_id'])
    rses = parse_expression(rule['rse_expression'])
    if admin_in_country:
        for rse in rses:
            if list_rse_attributes(rse=None, rse_id=rse['id']).get('country') in admin_in_country:
                return True

    # Only admin and country-admin are allowed to change locked state of rule
    if 'locked' in kwargs['options']:
        return False

    # Owner can change the rest of a rule
    if get_rule(kwargs['rule_id'])['account'] == issuer:
        return True

    return False


def perm_move_rule(issuer, kwargs):
    """
    Checks if an issuer can move a replication rule.

    :param issuer:   Account identifier which issues the command.
    :param kwargs:   List of arguments for the action.
    :returns:        True if account is allowed to call the API call, otherwise False
    """
    # Admin accounts can do everything
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True

    # Country admins are allowed to change the but need to be admin for the original, as well as future rule
    admin_in_country = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])

    admin_source = False
    admin_destination = False

    if admin_in_country:
        rule = get_rule(rule_id=kwargs['rule_id'])
        rses = parse_expression(rule['rse_expression'])
        for rse in rses:
            if list_rse_attributes(rse=None, rse_id=rse['id']).get('country') in admin_in_country:
                admin_source = True
                break

        rses = parse_expression(kwargs['rse_expression'])
        for rse in rses:
            if list_rse_attributes(rse=None, rse_id=rse['id']).get('country') in admin_in_country:
                admin_destination = True
                break

        if admin_source and admin_destination:
            return True

    return False


def perm_approve_rule(issuer, kwargs):
    """
    Checks if an issuer can approve a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    # Admin accounts can do everything
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True

    rule = get_rule(rule_id=kwargs['rule_id'])
    rses = parse_expression(rule['rse_expression'])

    # APPROVERS can approve the rule
    for rse in rses:
        rse_attr = list_rse_attributes(rse=rse['rse'])
        if rse_attr.get('rule_approvers'):
            if issuer in rse_attr.get('rule_approvers').split(','):
                return True

    # LOCALGROUPDISK/LOCALGROUPTAPE admins can approve the rule
    admin_in_country = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])
    if admin_in_country:
        for rse in rses:
            rse_attr = list_rse_attributes(rse=rse['rse'])
            if rse_attr.get('type', '') in ('LOCALGROUPDISK', 'LOCALGROUPTAPE'):
                if rse_attr.get('country', '') in admin_in_country:
                    return True

    # GROUPDISK admins can approve the rule
    admin_for_phys_group = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('group-') and kv['value'] == 'admin':
            admin_for_phys_group.append(kv['key'].partition('-')[2])
    if admin_for_phys_group:
        for rse in rses:
            rse_attr = list_rse_attributes(rse=rse['rse'])
            if rse_attr.get('type', '') == 'GROUPDISK':
                if rse_attr.get('physgroup', '') in admin_for_phys_group:
                    return True

    return False


def perm_reduce_rule(issuer, kwargs):
    """
    Checks if an issuer can reduce a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True
    return False


def perm_update_subscription(issuer, kwargs):
    """
    Checks if an account can update a subscription.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True

    return False


def perm_detach_dids(issuer, kwargs):
    """
    Checks if an account can detach an data identifier from the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return perm_attach_dids(issuer, kwargs)


def perm_set_metadata(issuer, kwargs):
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    cond = issuer == 'root' or has_account_attribute(account=issuer, key='admin')
    if kwargs['scope'] != 'archive':
        return cond or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer)
    meta = rucio.core.did.get_metadata(scope=kwargs['scope'], name=kwargs['name'])
    return cond or meta.get('account', False) == issuer


def perm_set_status(issuer, kwargs):
    """
    Checks if an account can set status on an data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if kwargs.get('open', False):
        if issuer != 'root' and not has_account_attribute(account=issuer, key='admin'):
            return False
    cond = (issuer == 'root' or has_account_attribute(account=issuer, key='admin'))
    if kwargs['scope'] != 'archive':
        return cond or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer)
    meta = rucio.core.did.get_metadata(scope=kwargs['scope'], name=kwargs['name'])
    return cond or meta.get('account', False) == issuer


def perm_add_protocol(issuer, kwargs):
    """
    Checks if an account can add a protocol to an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_del_protocol(issuer, kwargs):
    """
    Checks if an account can delete protocols from an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_update_protocol(issuer, kwargs):
    """
    Checks if an account can update protocols of an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_declare_bad_file_replicas(issuer, kwargs):
    """
    Checks if an account can declare bad file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    is_cloud_admin = bool([acc_attr for acc_attr in list_account_attributes(account=issuer) if (acc_attr['key'].startswith('cloud-')) and (acc_attr['value'] == 'admin')])
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin') or is_cloud_admin


def perm_declare_suspicious_file_replicas(issuer, kwargs):
    """
    Checks if an account can declare suspicious file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_add_replicas(issuer, kwargs):
    """
    Checks if an account can add replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    rse = str(kwargs.get('rse', ''))
    group = []

    for kv in list_account_attributes(account=issuer):
        if (kv['key'].startswith('group-') or kv['key'].startswith('country-')) and kv['value'] in ['admin', 'user']:
            group.append(kv['key'].partition('-')[2])
    rse_attr = list_rse_attributes(rse=rse)
    if group:
        if rse_attr.get('type', '') == 'GROUPDISK':
            if rse_attr.get('physgroup', '') in group:
                return True
        if rse_attr.get('type', '') == 'LOCALGROUPDISK':
            if rse_attr.get('country', '') in group:
                return True

    return rse_attr.get('type', '') in ['SCRATCHDISK', 'MOCK', 'TEST']\
        or issuer == 'root'\
        or has_account_attribute(account=issuer, key='admin')


def perm_skip_availability_check(issuer, kwargs):
    """
    Checks if an account can skip the availabity check to add/delete file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_delete_replicas(issuer, kwargs):
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return False


def perm_update_replicas_states(issuer, kwargs):
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    rse = str(kwargs.get('rse', ''))
    group = []

    for kv in list_account_attributes(account=issuer):
        if (kv['key'].startswith('group-') or kv['key'].startswith('country-')) and kv['value'] in ['admin', 'user']:
            group.append(kv['key'].partition('-')[2])
    rse_attr = list_rse_attributes(rse=rse)
    if group:
        if rse_attr.get('type', '') == 'GROUPDISK':
            if rse_attr.get('physgroup', '') in group:
                return True
        if rse_attr.get('type', '') == 'LOCALGROUPDISK':
            if rse_attr.get('country', '') in group:
                return True

    return rse_attr.get('type', '') in ['SCRATCHDISK', 'MOCK', 'TEST']\
        or issuer == 'root'\
        or has_account_attribute(account=issuer, key='admin')


def perm_queue_requests(issuer, kwargs):
    """
    Checks if an account can submit transfer or deletion requests on destination RSEs for data identifiers.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_query_request(issuer, kwargs):
    """
    Checks if an account can query a request.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_get_request_by_did(issuer, kwargs):
    """
    Checks if an account can get a request by DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_cancel_request(issuer, kwargs):
    """
    Checks if an account can cancel a request.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_get_next(issuer, kwargs):
    """
    Checks if an account can retrieve the next request matching the request type and state.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return issuer == 'root'


def perm_set_rse_usage(issuer, kwargs):
    """
    Checks if an account can set RSE usage information.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_set_rse_limits(issuer, kwargs):
    """
    Checks if an account can set RSE limits.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_set_account_limit(issuer, kwargs):
    """
    Checks if an account can set an account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True
    # Check if user is a country admin
    admin_in_country = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])
    if admin_in_country and list_rse_attributes(rse=kwargs['rse'], rse_id=None).get('country') in admin_in_country:
        return True
    return False


def perm_delete_account_limit(issuer, kwargs):
    """
    Checks if an account can delete an account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if issuer == 'root' or has_account_attribute(account=issuer, key='admin'):
        return True
    # Check if user is a country admin
    admin_in_country = []
    for kv in list_account_attributes(account=issuer):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])
    if admin_in_country and list_rse_attributes(rse=kwargs['rse'], rse_id=None).get('country') in admin_in_country:
        return True
    return False


def perm_config(issuer, kwargs):
    """
    Checks if an account can read/write the configuration.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_get_account_usage(issuer, kwargs):
    """
    Checks if an account can get the account usage of an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_add_account_attribute(issuer, kwargs):
    """
    Checks if an account can add attributes to accounts.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_del_account_attribute(issuer, kwargs):
    """
    Checks if an account can add attributes to accounts.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_add_account_attribute(issuer, kwargs)


def perm_list_heartbeats(issuer, kwargs):
    """
    Checks if an account can list heartbeats.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root'


def perm_resurrect(issuer, kwargs):
    """
    Checks if an account can resurrect DIDS.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_update_lifetime_exceptions(issuer, kwargs):
    """
    Checks if an account can approve/reject Lifetime Model exceptions.

    :param issuer: Account identifier which issues the command.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='admin')


def perm_get_ssh_challenge_token(issuer, kwargs):
    """
    Checks if an account can request a challenge token.

    :param issuer: Account identifier which issues the command.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return True


def perm_get_signed_url(issuer, kwargs):
    """
    Checks if an account can request a signed URL.

    :param issuer: Account identifier which issues the command.
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return issuer == 'root' or has_account_attribute(account=issuer, key='sign-gcs')


def perm_add_bad_pfns(issuer, kwargs):
    """
    Checks if an account can declare bad PFNs.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :returns: True if account is allowed, otherwise False
    """
    if kwargs['state'] in [str(BadPFNStatus.BAD), str(BadPFNStatus.TEMPORARY_UNAVAILABLE)]:
        is_cloud_admin = bool([acc_attr for acc_attr in list_account_attributes(account=issuer) if (acc_attr['key'].startswith('cloud-')) and (acc_attr['value'] == 'admin')])
        return issuer == 'root' or has_account_attribute(account=issuer, key='admin') or is_cloud_admin
    elif kwargs['state'] == str(BadPFNStatus.SUSPICIOUS):
        return True
    return issuer == 'root'
