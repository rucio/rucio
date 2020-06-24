'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2016-2017
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
 - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
 - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
'''

from nose.tools import assert_equal

from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid
from rucio.core.quarantined_replica import (add_quarantined_replicas,
                                            list_quarantined_replicas,
                                            delete_quarantined_replicas)
from rucio.core.rse import get_rse_id


def test_quarantined_replicas():
    """ QUARANTINED REPLICA (CORE): Add, List and Delete quarantined replicas """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
    else:
        vo = {}

    rse_id = get_rse_id(rse='MOCK', **vo)

    quarantined_replicas = len(list_quarantined_replicas(rse_id=rse_id, limit=10000))

    nbreplicas = 5

    replicas = [{'path': '/path/' + generate_uuid()} for _ in range(nbreplicas)]

    add_quarantined_replicas(rse_id=rse_id, replicas=replicas)

    assert_equal(quarantined_replicas + nbreplicas, len(list_quarantined_replicas(rse_id=rse_id, limit=10000)))

    delete_quarantined_replicas(rse_id=rse_id, replicas=replicas)

    assert_equal(quarantined_replicas, len(list_quarantined_replicas(rse_id=rse_id, limit=10000)))
