# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
# - Radu Carpa <radu.carpa@cern.ch>, 2021

import pytest

from rucio.common.exception import NoDistance
from rucio.core.distance import add_distance, update_distances
from rucio.core.replica import add_replicas
from rucio.core.transfer import get_hops, get_transfer_requests_and_source_replicas
from rucio.core import rule as rule_core
from rucio.core import request as request_core
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType
from rucio.db.sqla.session import transactional_session
from rucio.common.utils import generate_uuid


def test_get_hops(rse_factory):
    # Build the following topology:
    # +------+           +------+     10    +------+
    # |      |     40    |      +-----------+      |
    # | RSE0 |  +--------+ RSE1 |           | RSE2 +-------------+
    # |      |  |        |      |      +----+      |             |
    # +------+  |        +------+      |    +------+             | <missing_cost>
    #           |                      |                         |
    #           |                      |                         |
    #           |                      |                         |
    # +------+  |        +------+  10  |    +------+           +-+----+
    # |      +--+        |      +------+    |      |   --20->  |      |
    # | RSE3 |   --10->  | RSE4 |           | RSE5 +-->--->--->+ RSE6 |
    # |      +-->--->--->+      +-----------+      |           |      |
    # +----+-+           +------+     10    +-+----+           +------+
    #      |                                  |
    #      |                50                |
    #      +----------------------------------+
    #
    _, rse0_id = rse_factory.make_mock_rse()
    _, rse1_id = rse_factory.make_mock_rse()
    _, rse2_id = rse_factory.make_mock_rse()
    _, rse3_id = rse_factory.make_mock_rse()
    _, rse4_id = rse_factory.make_mock_rse()
    _, rse5_id = rse_factory.make_mock_rse()
    _, rse6_id = rse_factory.make_mock_rse()
    all_rses = [rse0_id, rse1_id, rse2_id, rse3_id, rse4_id, rse5_id, rse6_id]

    add_distance(rse1_id, rse3_id, ranking=40)
    add_distance(rse1_id, rse2_id, ranking=10)

    add_distance(rse2_id, rse1_id, ranking=10)
    add_distance(rse2_id, rse4_id, ranking=10)

    add_distance(rse3_id, rse1_id, ranking=40)
    add_distance(rse3_id, rse4_id, ranking=10)
    add_distance(rse3_id, rse5_id, ranking=50)

    add_distance(rse4_id, rse2_id, ranking=10)
    add_distance(rse4_id, rse5_id, ranking=10)

    add_distance(rse5_id, rse3_id, ranking=50)
    add_distance(rse5_id, rse4_id, ranking=10)
    add_distance(rse5_id, rse6_id, ranking=20)

    # There must be no paths between an isolated node and other nodes; be it with multipath enabled or disabled
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse0_id, dest_rse_id=rse1_id)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse1_id, dest_rse_id=rse0_id)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse0_id, dest_rse_id=rse1_id, include_multihop=True, multihop_rses=all_rses)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse1_id, dest_rse_id=rse0_id, include_multihop=True, multihop_rses=all_rses)

    # A single hop path must be found between two directly connected RSE
    [hop] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse2_id)
    assert hop['source_rse_id'] == rse1_id
    assert hop['dest_rse_id'] == rse2_id

    # No path will be found if there is no direct connection and "include_multihop" is not set
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id)

    # Multihop_rses argument empty (not set), no path will be computed
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id, include_multihop=True)

    # The shortest multihop path will be computed
    [hop1, hop2] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id, include_multihop=True, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse3_id
    assert hop1['dest_rse_id'] == rse4_id
    assert hop2['source_rse_id'] == rse4_id
    assert hop2['dest_rse_id'] == rse2_id

    # multihop_rses doesn't contain the RSE needed for the shortest path. Return a longer path
    [hop1, hop2] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse4_id, include_multihop=True, multihop_rses=[rse3_id])
    assert hop1['source_rse_id'] == rse1_id
    assert hop1['dest_rse_id'] == rse3_id
    assert hop2['source_rse_id'] == rse3_id
    assert hop2['dest_rse_id'] == rse4_id

    # A direct connection is preferred over a multihop one with smaller cost
    [hop] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse5_id, include_multihop=True, multihop_rses=all_rses)
    assert hop['source_rse_id'] == rse3_id
    assert hop['dest_rse_id'] == rse5_id

    # A link with cost only in one direction will not be used in the opposite direction
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse6_id, dest_rse_id=rse5_id, include_multihop=True, multihop_rses=all_rses)
    [hop1, hop2] = get_hops(source_rse_id=rse4_id, dest_rse_id=rse3_id, include_multihop=True, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse4_id
    assert hop2['source_rse_id'] == rse5_id
    assert hop2['dest_rse_id'] == rse3_id

    # A longer path is preferred over a shorter one with high intermediate cost
    [hop1, hop2, hop3] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse6_id, include_multihop=True, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse3_id
    assert hop2['source_rse_id'] == rse4_id
    assert hop3['source_rse_id'] == rse5_id
    assert hop3['dest_rse_id'] == rse6_id

    # A link with no cost is ignored. Both for direct connection and multihop paths
    [hop1, hop2, hop3] = get_hops(source_rse_id=rse2_id, dest_rse_id=rse6_id, include_multihop=True, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse2_id
    assert hop2['source_rse_id'] == rse4_id
    assert hop3['source_rse_id'] == rse5_id
    assert hop3['dest_rse_id'] == rse6_id
    [hop1, hop2, hop3, hop4] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse6_id, include_multihop=True, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse1_id
    assert hop2['source_rse_id'] == rse2_id
    assert hop3['source_rse_id'] == rse4_id
    assert hop4['source_rse_id'] == rse5_id
    assert hop4['dest_rse_id'] == rse6_id


def test_disk_vs_tape_priority(rse_factory, root_account, mock_scope):
    tape1_rse_name, tape1_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.TAPE)
    tape2_rse_name, tape2_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.TAPE)
    disk1_rse_name, disk1_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.DISK)
    disk2_rse_name, disk2_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.DISK)
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    source_rses = [tape1_rse_id, tape2_rse_id, disk1_rse_id, disk2_rse_id]
    all_rses = source_rses + [dst_rse_id]

    # add same file to all source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in source_rses:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    @transactional_session
    def __fake_source_ranking(source_rse_id, new_ranking, session=None):
        rowcount = session.query(models.Source).filter(models.Source.rse_id == source_rse_id).update({'ranking': new_ranking})
        if not rowcount:
            models.Source(request_id=request['id'],
                          scope=request['scope'],
                          name=request['name'],
                          rse_id=source_rse_id,
                          dest_rse_id=request['dest_rse_id'],
                          ranking=new_ranking,
                          bytes=request['bytes'],
                          url=None,
                          is_using=False). \
                save(session=session, flush=False)

    # Init all distances to the same value
    for rse_id in source_rses:
        add_distance(rse_id, dst_rse_id, ranking=10)

    # On equal priority and distance, disk should be preferred over tape. Both disk sources will be returned
    transfers, _reqs_no_source, _reqs_scheme_mismatch, _reqs_only_tape_source = get_transfer_requests_and_source_replicas(rses=all_rses)
    assert len(transfers) == 1
    transfer = next(iter(transfers.values()))
    assert len(transfer['sources']) == 2
    assert transfer['sources'][0][0] in (disk1_rse_name, disk2_rse_name)

    # Change the rating of the disk RSEs. Tape RSEs must now be preferred.
    # Multiple tape sources are not allowed. Only one tape RSE source must be returned.
    __fake_source_ranking(disk1_rse_id, -1)
    __fake_source_ranking(disk2_rse_id, -1)
    transfers, _reqs_no_source, _reqs_scheme_mismatch, _reqs_only_tape_source = get_transfer_requests_and_source_replicas(rses=all_rses)
    assert len(transfers) == 1
    transfer = next(iter(transfers.values()))
    assert len(transfer['sources']) == 1
    assert transfer['sources'][0][0] in (tape1_rse_name, tape2_rse_name)

    # On equal source ranking, but different distance; the smaller distance is preferred
    update_distances(tape1_rse_id, dst_rse_id, parameters={'ranking': 15})
    transfers, _reqs_no_source, _reqs_scheme_mismatch, _reqs_only_tape_source = get_transfer_requests_and_source_replicas(rses=all_rses)
    assert len(transfers) == 1
    transfer = next(iter(transfers.values()))
    assert len(transfer['sources']) == 1
    assert transfer['sources'][0][0] == tape2_rse_name

    # On different source ranking, the bigger ranking is preferred
    __fake_source_ranking(tape2_rse_id, -1)
    transfers, _reqs_no_source, _reqs_scheme_mismatch, _reqs_only_tape_source = get_transfer_requests_and_source_replicas(rses=all_rses)
    assert len(transfers) == 1
    transfer = next(iter(transfers.values()))
    assert len(transfer['sources']) == 1
    assert transfer['sources'][0][0] == tape1_rse_name
