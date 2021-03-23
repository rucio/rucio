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
from rucio.core.distance import add_distance
from rucio.core.transfer import get_hops


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
