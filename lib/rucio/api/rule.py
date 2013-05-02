# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from datetime import datetime, timedelta

from rucio.api.permission import has_permission
from rucio.common.exception import AccessDenied
from rucio.core import rule


def add_replication_rule(dids, copies, rse_expression, weight, lifetime, grouping, account, locked, subscription_id, issuer):
    """
    Adds a replication rule.

    :param dids:             The data identifier set.
    :param copies:           The number of replicas.
    :param rse_expression:   Boolean string expression to give the list of RSEs.
    :param weight:           If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
    :param lifetime:         The lifetime of the replication rules (in hours).
    :param grouping:         ALL -  All files will be replicated to the same RSE.
                             DATASET - All files in the same dataset will be replicated to the same RSE.
                             NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    :param account:          The account owning the rule.
    :param locked:           If the rule is locked, it cannot be deleted.
    :param issuer:           The issuing account of this operation.
    :param subscription_id:  The subscription_id, if the rule is created by a subscription
    :returns:                List of created replication rules
    """
    kwargs = {'dids': dids, 'copies': copies, 'rse_expression': rse_expression, 'weight': weight, 'lifetime': lifetime, 'grouping': grouping, 'account': account, 'locked': locked, 'subscription_id': subscription_id}
    if not has_permission(issuer=issuer, action='add_rule', kwargs=kwargs):
        raise AccessDenied('Account %s can not add replication rule' % (issuer))
    #TODO Check for valid parameters: dids, copies etc.
    if lifetime:
        lifetime = datetime.utcnow() + timedelta(seconds=lifetime)
    return rule.add_replication_rule(account=account, dids=dids, copies=copies, rse_expression=rse_expression, grouping=grouping, weight=weight, lifetime=lifetime, locked=locked, subscription_id=subscription_id)


def get_replication_rule(filters={}):
    raise NotImplementedError


def delete_replication_rule(rule_id, issuer):
    """
    Deletes a replication rule and all associated locks.

    :param rule_id:  The id of the rule to be deleted
    :param issuer:   The issuing account of this operation
    :raises:         RuleNotFound
    """
    kwargs = {'rule_id': rule_id}
    if not has_permission(issuer=issuer, action='del_rule', kwargs=kwargs):
        raise AccessDenied('Account %s can not remove this replication rule.' % (issuer))
    rule.delete_replication_rule(rule_id)


def set_replication_rule():
    raise NotImplementedError
