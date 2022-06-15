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

from rucio.api.permission import has_permission
from rucio.common.config import config_get_bool
from rucio.common.exception import AccessDenied
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict
from rucio.core import rule
from rucio.db.sqla.session import read_session, stream_session, transactional_session


@read_session
def is_multi_vo(session=None):
    """
    Check whether this instance is configured for multi-VO
    returns: Boolean True if running in multi-VO
    """
    return config_get_bool('common', 'multi_vo', raise_exception=False, default=False, session=session)


@transactional_session
def add_replication_rule(dids, copies, rse_expression, weight, lifetime, grouping, account, locked, subscription_id, source_replica_expression,
                         activity, notify, purge_replicas, ignore_availability, comment, ask_approval, asynchronous, delay_injection, priority,
                         split_container, meta, issuer, vo='def', session=None):
    """
    Adds a replication rule.

    :param dids:                       The data identifier set.
    :param copies:                     The number of replicas.
    :param rse_expression:             Boolean string expression to give the list of RSEs.
    :param weight:                     If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
    :param lifetime:                   The lifetime of the replication rules (in seconds).
    :param grouping:                   ALL -  All files will be replicated to the same RSE.
                                       DATASET - All files in the same dataset will be replicated to the same RSE.
                                       NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    :param account:                    The account owning the rule.
    :param locked:                     If the rule is locked, it cannot be deleted.
    :param subscription_id:            The subscription_id, if the rule is created by a subscription.
    :param source_replica_expression:  Only use replicas from this RSE as sources.
    :param activity:                   Activity to be passed on to the conveyor.
    :param notify:                     Notification setting of the rule.
    :purge purge_replicas:             The purge setting to delete replicas immediately after rule deletion.
    :param ignore_availability:        Option to ignore the availability of RSEs.
    :param comment:                    Comment about the rule.
    :param ask_approval:               Ask for approval of this rule.
    :param asynchronous:               Create rule asynchronously by judge-injector.
    :param priority:                   Priority of the transfers.
    :param split_container:            Should a container rule be split into individual dataset rules.
    :param meta:                       WFMS metadata as a dictionary.
    :param issuer:                     The issuing account of this operation.
    :param vo:                         The VO to act on.
    :param session:                    The database session in use.
    :returns:                          List of created replication rules.
    """
    if account is None:
        account = issuer

    if activity is None:
        activity = 'User Subscriptions'

    kwargs = {'dids': dids, 'copies': copies, 'rse_expression': rse_expression, 'weight': weight, 'lifetime': lifetime,
              'grouping': grouping, 'account': account, 'locked': locked, 'subscription_id': subscription_id,
              'source_replica_expression': source_replica_expression, 'notify': notify, 'activity': activity,
              'purge_replicas': purge_replicas, 'ignore_availability': ignore_availability, 'comment': comment,
              'ask_approval': ask_approval, 'asynchronous': asynchronous, 'delay_injection': delay_injection, 'priority': priority,
              'split_container': split_container, 'meta': meta}

    validate_schema(name='rule', obj=kwargs, vo=vo)

    if not has_permission(issuer=issuer, vo=vo, action='add_rule', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not add replication rule' % (issuer))

    account = InternalAccount(account, vo=vo)
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)

    return rule.add_rule(account=account,
                         dids=dids,
                         copies=copies,
                         rse_expression=rse_expression,
                         grouping=grouping,
                         weight=weight,
                         lifetime=lifetime,
                         locked=locked,
                         subscription_id=subscription_id,
                         source_replica_expression=source_replica_expression,
                         activity=activity,
                         notify=notify,
                         purge_replicas=purge_replicas,
                         ignore_availability=ignore_availability,
                         comment=comment,
                         ask_approval=ask_approval,
                         asynchronous=asynchronous,
                         delay_injection=delay_injection,
                         priority=priority,
                         split_container=split_container,
                         meta=meta,
                         session=session)


@read_session
def get_replication_rule(rule_id, issuer, vo='def', session=None):
    """
    Get replication rule by it's id.

    :param rule_id: The rule_id to get.
    :param issuer: The issuing account of this operation.
    :param vo: The VO of the issuer.
    :param session: The database session in use.
    """
    kwargs = {'rule_id': rule_id}
    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    result = rule.get_rule(rule_id, session=session)
    return api_update_return_dict(result, session=session)


@stream_session
def list_replication_rules(filters={}, vo='def', session=None):
    """
    Lists replication rules based on a filter.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    # If filters is empty, create a new dict to avoid overwriting the function's default
    if not filters:
        filters = {}

    if 'scope' in filters:
        scope = filters['scope']
    else:
        scope = '*'
    filters['scope'] = InternalScope(scope=scope, vo=vo)

    if 'account' in filters:
        account = filters['account']
    else:
        account = '*'
    filters['account'] = InternalAccount(account=account, vo=vo)

    rules = rule.list_rules(filters, session=session)
    for r in rules:
        yield api_update_return_dict(r, session=session)


@read_session
def list_replication_rule_history(rule_id, issuer, vo='def', session=None):
    """
    Lists replication rule history..

    :param rule_id: The rule_id to list.
    :param issuer: The issuing account of this operation.
    :param vo: The VO of the issuer.
    :param session: The database session in use.
    """
    kwargs = {'rule_id': rule_id}
    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    return rule.list_rule_history(rule_id, session=session)


@stream_session
def list_replication_rule_full_history(scope, name, vo='def', session=None):
    """
    List the rule history of a DID.

    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    scope = InternalScope(scope, vo=vo)
    rules = rule.list_rule_full_history(scope, name, session=session)
    for r in rules:
        yield api_update_return_dict(r, session=session)


@stream_session
def list_associated_replication_rules_for_file(scope, name, vo='def', session=None):
    """
    Lists associated replication rules by file.

    :param scope: Scope of the file..
    :param name:  Name of the file.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    scope = InternalScope(scope, vo=vo)
    rules = rule.list_associated_rules_for_file(scope=scope, name=name, session=session)
    for r in rules:
        yield api_update_return_dict(r, session=session)


@transactional_session
def delete_replication_rule(rule_id, purge_replicas, issuer, vo='def', session=None):
    """
    Deletes a replication rule and all associated locks.

    :param rule_id:        The id of the rule to be deleted
    :param purge_replicas: Purge the replicas immediately
    :param issuer:         The issuing account of this operation
    :param vo:             The VO to act on.
    :param session:        The database session in use.
    :raises:               RuleNotFound, AccessDenied
    """
    kwargs = {'rule_id': rule_id, 'purge_replicas': purge_replicas}
    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    if not has_permission(issuer=issuer, vo=vo, action='del_rule', kwargs=kwargs):
        raise AccessDenied('Account %s can not remove this replication rule.' % (issuer))
    rule.delete_rule(rule_id=rule_id, purge_replicas=purge_replicas, soft=True, session=session)


@transactional_session
def update_replication_rule(rule_id, options, issuer, vo='def', session=None):
    """
    Update lock state of a replication rule.

    :param rule_id:     The rule_id to lock.
    :param options:     Options dictionary.
    :param issuer:      The issuing account of this operation
    :param vo:          The VO to act on.
    :param session:     The database session in use.
    :raises:            RuleNotFound if no Rule can be found.
    """
    kwargs = {'rule_id': rule_id, 'options': options}
    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    if 'approve' in options:
        if not has_permission(issuer=issuer, vo=vo, action='approve_rule', kwargs=kwargs, session=session):
            raise AccessDenied('Account %s can not approve/deny this replication rule.' % (issuer))

        issuer = InternalAccount(issuer, vo=vo)
        if options['approve']:
            rule.approve_rule(rule_id=rule_id, approver=issuer, session=session)
        else:
            rule.deny_rule(rule_id=rule_id, approver=issuer, reason=options.get('comment', None), session=session)
    else:
        if not has_permission(issuer=issuer, vo=vo, action='update_rule', kwargs=kwargs, session=session):
            raise AccessDenied('Account %s can not update this replication rule.' % (issuer))
        if 'account' in options:
            options['account'] = InternalAccount(options['account'], vo=vo)
        rule.update_rule(rule_id=rule_id, options=options, session=session)


@transactional_session
def reduce_replication_rule(rule_id, copies, exclude_expression, issuer, vo='def', session=None):
    """
    Reduce the number of copies for a rule by atomically replacing the rule.

    :param rule_id:             Rule to be reduced.
    :param copies:              Number of copies of the new rule.
    :param exclude_expression:  RSE Expression of RSEs to exclude.
    :param issuer:              The issuing account of this operation
    :param vo:                  The VO to act on.
    :param session:             The database session in use.
    :raises:                    RuleReplaceFailed, RuleNotFound
    """
    kwargs = {'rule_id': rule_id, 'copies': copies, 'exclude_expression': exclude_expression}
    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    if not has_permission(issuer=issuer, vo=vo, action='reduce_rule', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not reduce this replication rule.' % (issuer))

    return rule.reduce_rule(rule_id=rule_id, copies=copies, exclude_expression=exclude_expression, session=session)


@read_session
def examine_replication_rule(rule_id, issuer, vo='def', session=None):
    """
    Examine a replication rule.

    :param rule_id: The rule_id to get.
    :param issuer: The issuing account of this operation.
    :param vo: The VO of the issuer.
    :param session: The database session in use.
    """
    kwargs = {'rule_id': rule_id}
    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    result = rule.examine_rule(rule_id, session=session)
    result = api_update_return_dict(result, session=session)
    if 'transfers' in result:
        result['transfers'] = [api_update_return_dict(t, session=session) for t in result['transfers']]
    return result


@transactional_session
def move_replication_rule(rule_id, rse_expression, override, issuer, vo='def', session=None):
    """
    Move a replication rule to another RSE and, once done, delete the original one.

    :param rule_id:                    Rule to be moved.
    :param rse_expression:             RSE expression of the new rule.
    :param override:                   Configurations to update for the new rule.
    :param session:                    The DB Session.
    :param vo:                         The VO to act on.
    :raises:                           RuleNotFound, RuleReplaceFailed, InvalidRSEExpression, AccessDenied
    """
    kwargs = {
        'rule_id': rule_id,
        'rse_expression': rse_expression,
        'override': override,
    }

    if is_multi_vo(session=session) and not has_permission(issuer=issuer, vo=vo, action='access_rule_vo', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not access rules at other VOs.' % (issuer))
    if not has_permission(issuer=issuer, vo=vo, action='move_rule', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not move this replication rule.' % (issuer))

    return rule.move_rule(**kwargs, session=session)
