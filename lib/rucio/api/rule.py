# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from rucio.api.permission import has_permission
from rucio.common.exception import AccessDenied
from rucio.core import rule


def add_replication_rule(dids, copies, rse_expression, parameters, issuer):
    """
    Adds a replication rule.

    :param dids:            The data identifier set.
    :param copies:          The number of replicas.
    :param rse_expression:  Boolean string expression to give the list of RSEs.
    :param weight:          If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
    :param lifetime:        The lifetime of the replication rules (remaining time/duration).
    :param grouping:        all -  All files will be replicated to the same RSE.
                            dataset - All files in the same dataset will be replicated to the same RSE;
                            none - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    """
    kwargs = {'dids': dids, 'copies': copies, 'rse_expression': rse_expression, 'parameters': parameters}
    if not has_permission(issuer=issuer, action='add_replication_rule', kwargs=kwargs):
        raise AccessDenied('Account %s can not add replication rule' % (issuer))
    return rule.add_replication_rule(account=issuer, dids=dids, copies=copies, rse_expression=rse_expression, parameters=parameters)


def list_replication_rules(filters={}):
    raise NotImplementedError


def delete_replication_rule(scope, lfn, rse_tag):
    """
    Deletes a replication rule.

    :param scope: The scope name.
    :param lfn: The file identifier (LFN).
    :param rse_tag: The file location (RSE).

    """
    raise NotImplementedError


def set_replication_rule(scope, lfn, rse_tag):
    """
    Sets a replication rule.

    :param scope: The scope name.
    :param lfn: The file identifier (LFN).
    :param rse_tag: The file location (RSE).

    """
    raise NotImplementedError
