# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from rucio.common.types import InternalScope
from rucio.common.utils import api_update_return_dict
from rucio.core import lock
from rucio.core.rse import get_rse_id


def get_dataset_locks(scope, name):
    """
    Get the dataset locks of a dataset.

    :param scope:          Scope of the dataset.
    :param name:           Name of the dataset.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    scope = InternalScope(scope)

    locks = lock.get_dataset_locks(scope=scope, name=name)

    for l in locks:
        yield api_update_return_dict(l)


def get_dataset_locks_by_rse(rse):
    """
    Get the dataset locks of an RSE.

    :param rse:            RSE name.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    rse_id = get_rse_id(rse=rse)
    locks = lock.get_dataset_locks_by_rse_id(rse_id=rse_id)

    for l in locks:
        yield api_update_return_dict(l)


def get_replica_locks_for_rule_id(rule_id):
    """
    Get the replica locks for a rule_id.

    :param rule_id:     Rule ID.
    :return:            List of dicts.
    """

    locks = lock.get_replica_locks_for_rule_id(rule_id=rule_id)

    for l in locks:
        yield api_update_return_dict(l)
