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

import pytest

from rucio.common.config import config_get_bool
from rucio.common.utils import generate_uuid
from rucio.core.quarantined_replica import add_quarantined_replicas, list_quarantined_replicas, \
    delete_quarantined_replicas
from rucio.core.rse import get_rse_id
from rucio.tests.common_server import get_vo


@pytest.mark.noparallel(reason='uses pre-defined rses')
def test_quarantined_replicas():
    """ QUARANTINED REPLICA (CORE): Add, List and Delete quarantined replicas """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}

    rse_id = get_rse_id(rse='MOCK', **vo)

    real_replicas, dark_replicas = list_quarantined_replicas(rse_id=rse_id, limit=10000)
    quarantined_replicas = len(real_replicas) + len(dark_replicas)

    nbreplicas = 5

    replicas = [{'path': '/path/' + generate_uuid()} for _ in range(nbreplicas)]

    add_quarantined_replicas(rse_id=rse_id, replicas=replicas)

    real_replicas, dark_replicas = list_quarantined_replicas(rse_id=rse_id, limit=10000)
    assert quarantined_replicas + nbreplicas == len(dark_replicas) + len(real_replicas)

    delete_quarantined_replicas(rse_id=rse_id, replicas=replicas)

    real_replicas, dark_replicas = list_quarantined_replicas(rse_id=rse_id, limit=10000)
    assert quarantined_replicas == len(dark_replicas) + len(real_replicas)
