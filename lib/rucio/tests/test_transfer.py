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
from concurrent.futures import ThreadPoolExecutor

from rucio.common.exception import NoDistance
from rucio.core.distance import add_distance
from rucio.core.replica import add_replicas
from rucio.core.request import list_transfer_requests_and_source_replicas
from rucio.core.transfer import build_transfer_paths
from rucio.core.topology import get_hops, Topology
from rucio.core import rule as rule_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType, RequestState
from rucio.db.sqla.session import transactional_session, get_session
from rucio.common.utils import generate_uuid
from rucio.daemons.conveyor.common import next_transfers_to_submit, assign_paths_to_transfertool_and_create_hops


@transactional_session
def __fake_source_ranking(request, source_rse_id, new_ranking, session=None):
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
    all_rses = {rse0_id, rse1_id, rse2_id, rse3_id, rse4_id, rse5_id, rse6_id}

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
        get_hops(source_rse_id=rse0_id, dest_rse_id=rse1_id, multihop_rses=all_rses)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse1_id, dest_rse_id=rse0_id, multihop_rses=all_rses)

    # A single hop path must be found between two directly connected RSE
    [hop] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse2_id)
    assert hop['source_rse_id'] == rse1_id
    assert hop['dest_rse_id'] == rse2_id

    # No path will be found if there is no direct connection and "include_multihop" is not set
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id)

    # No multihop rses given, multihop disabled
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id, multihop_rses=set())

    # The shortest multihop path will be computed
    [hop1, hop2] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse3_id
    assert hop1['dest_rse_id'] == rse4_id
    assert hop2['source_rse_id'] == rse4_id
    assert hop2['dest_rse_id'] == rse2_id

    # multihop_rses doesn't contain the RSE needed for the shortest path. Return a longer path
    [hop1, hop2] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse4_id, multihop_rses={rse3_id})
    assert hop1['source_rse_id'] == rse1_id
    assert hop1['dest_rse_id'] == rse3_id
    assert hop2['source_rse_id'] == rse3_id
    assert hop2['dest_rse_id'] == rse4_id

    # A link with cost only in one direction will not be used in the opposite direction
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse6_id, dest_rse_id=rse5_id, multihop_rses=all_rses)
    [hop1, hop2] = get_hops(source_rse_id=rse4_id, dest_rse_id=rse3_id, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse4_id
    assert hop2['source_rse_id'] == rse5_id
    assert hop2['dest_rse_id'] == rse3_id

    # A longer path is preferred over a shorter one with high intermediate cost
    [hop1, hop2, hop3] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse6_id, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse3_id
    assert hop2['source_rse_id'] == rse4_id
    assert hop3['source_rse_id'] == rse5_id
    assert hop3['dest_rse_id'] == rse6_id

    # A link with no cost is ignored. Both for direct connection and multihop paths
    [hop1, hop2, hop3] = get_hops(source_rse_id=rse2_id, dest_rse_id=rse6_id, multihop_rses=all_rses)
    assert hop1['source_rse_id'] == rse2_id
    assert hop2['source_rse_id'] == rse4_id
    assert hop3['source_rse_id'] == rse5_id
    assert hop3['dest_rse_id'] == rse6_id
    [hop1, hop2, hop3, hop4] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse6_id, multihop_rses=all_rses)
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
    add_distance(disk1_rse_id, dst_rse_id, ranking=15)
    add_distance(disk2_rse_id, dst_rse_id, ranking=10)
    add_distance(tape1_rse_id, dst_rse_id, ranking=15)
    add_distance(tape2_rse_id, dst_rse_id, ranking=10)

    # add same file to all source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in source_rses:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    # On equal priority and distance, disk should be preferred over tape. Both disk sources will be returned
    [[_, [transfer]]] = next_transfers_to_submit(rses=all_rses).items()
    assert len(transfer[0].legacy_sources) == 2
    assert transfer[0].legacy_sources[0][0] in (disk1_rse_name, disk2_rse_name)

    # Change the rating of the disk RSEs. Disk still preferred, because it must fail twice before tape is tried
    __fake_source_ranking(request, disk1_rse_id, -1)
    __fake_source_ranking(request, disk2_rse_id, -1)
    [[_, [transfer]]] = next_transfers_to_submit(rses=all_rses).items()
    assert len(transfer[0].legacy_sources) == 2
    assert transfer[0].legacy_sources[0][0] in (disk1_rse_name, disk2_rse_name)

    # Change the rating of the disk RSEs again. Tape RSEs must now be preferred.
    # Multiple tape sources are not allowed. Only one tape RSE source must be returned.
    __fake_source_ranking(request, disk1_rse_id, -2)
    __fake_source_ranking(request, disk2_rse_id, -2)
    [[_, transfers]] = next_transfers_to_submit(rses=all_rses).items()
    assert len(transfers) == 1
    transfer = transfers[0]
    assert len(transfer[0].legacy_sources) == 1
    assert transfer[0].legacy_sources[0][0] in (tape1_rse_name, tape2_rse_name)

    # On equal source ranking, but different distance; the smaller distance is preferred
    [[_, [transfer]]] = next_transfers_to_submit(rses=all_rses).items()
    assert len(transfer[0].legacy_sources) == 1
    assert transfer[0].legacy_sources[0][0] == tape2_rse_name

    # On different source ranking, the bigger ranking is preferred
    __fake_source_ranking(request, tape2_rse_id, -1)
    [[_, [transfer]]] = next_transfers_to_submit(rses=all_rses).items()
    assert len(transfer[0].legacy_sources) == 1
    assert transfer[0].legacy_sources[0][0] == tape1_rse_name


@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_multihop_requests_created(rse_factory, did_factory, root_account, core_config_mock, caches_mock):
    """
    Ensure that multihop transfers are handled and intermediate request correctly created
    """
    rs0_name, src_rse_id = rse_factory.make_posix_rse()
    _, intermediate_rse_id = rse_factory.make_posix_rse()
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    rse_core.add_rse_attribute(intermediate_rse_id, 'available_for_multihop', True)

    add_distance(src_rse_id, intermediate_rse_id, ranking=10)
    add_distance(intermediate_rse_id, dst_rse_id, ranking=10)

    did = did_factory.upload_test_file(rs0_name)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    [[_, [transfer]]] = next_transfers_to_submit(rses=rse_factory.created_rses).items()
    # the intermediate request was correctly created
    assert request_core.get_request_by_did(rse_id=intermediate_rse_id, **did)


@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_multihop_concurrent_submitters(rse_factory, did_factory, root_account, core_config_mock, caches_mock):
    """
    Ensure that multiple concurrent submitters on the same multi-hop don't result in an undesired database state
    """
    src_rse, src_rse_id = rse_factory.make_posix_rse()
    jump_rse, jump_rse_id = rse_factory.make_posix_rse()
    dst_rse, dst_rse_id = rse_factory.make_posix_rse()
    rse_core.add_rse_attribute(jump_rse_id, 'available_for_multihop', True)

    add_distance(src_rse_id, jump_rse_id, ranking=10)
    add_distance(jump_rse_id, dst_rse_id, ranking=10)

    did = did_factory.upload_test_file(src_rse)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    nb_threads = 9
    nb_executions = 18
    with ThreadPoolExecutor(max_workers=nb_threads) as executor:
        futures = [executor.submit(next_transfers_to_submit, rses=rse_factory.created_rses) for _ in range(nb_executions)]
        for f in futures:
            try:
                f.result()
            except Exception:
                pass

    jmp_request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    dst_request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert jmp_request['state'] == dst_request['state'] == RequestState.QUEUED
    assert jmp_request['attributes']['source_replica_expression'] == src_rse
    assert jmp_request['attributes']['is_intermediate_hop']


@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_singlehop_vs_multihop_priority(rse_factory, root_account, mock_scope, core_config_mock, caches_mock):
    """
    On small distance difference, singlehop is prioritized over multihop
    due to HOP_PENALTY. On big difference, multihop is prioritized
    """
    # +------+    +------+
    # |      | 10 |      |
    # | RSE0 +--->| RSE1 |
    # |      |    |      +-+ 10
    # +------+    +------+ |  +------+       +------+
    #                      +->|      |  200  |      |
    # +------+                | RSE3 |<------| RSE4 |
    # |      |   30      +--->|      |       |      |
    # | RSE2 +-----------+    +------+       +------+
    # |      |
    # +------+
    _, rse0_id = rse_factory.make_posix_rse()
    _, rse1_id = rse_factory.make_posix_rse()
    _, rse2_id = rse_factory.make_posix_rse()
    rse3_name, rse3_id = rse_factory.make_posix_rse()
    _, rse4_id = rse_factory.make_posix_rse()

    add_distance(rse0_id, rse1_id, ranking=10)
    add_distance(rse1_id, rse3_id, ranking=10)
    add_distance(rse2_id, rse3_id, ranking=30)
    add_distance(rse4_id, rse3_id, ranking=200)
    rse_core.add_rse_attribute(rse1_id, 'available_for_multihop', True)

    # add same file to two source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in [rse0_id, rse2_id]:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=rse3_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    # The singlehop must be prioritized
    [[_, [transfer]]] = next_transfers_to_submit(rses=rse_factory.created_rses).items()
    assert len(transfer) == 1
    assert transfer[0].src.rse.id == rse2_id
    assert transfer[0].dst.rse.id == rse3_id

    # add same file to two source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in [rse0_id, rse4_id]:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=rse3_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    # The multihop must be prioritized
    [[_, transfers]] = next_transfers_to_submit(rses=rse_factory.created_rses).items()
    transfer = next(iter(t for t in transfers if t[0].rws.name == file['name']))
    assert len(transfer) == 2


def test_fk_error_on_source_creation(rse_factory, did_factory, root_account):
    """
    verify that ensure_db_sources correctly handles foreign key errors while creating sources
    """

    if get_session().bind.dialect.name == 'sqlite':
        pytest.skip('Will not run on sqlite')

    src_rse, src_rse_id = rse_factory.make_mock_rse()
    dst_rse, dst_rse_id = rse_factory.make_mock_rse()
    add_distance(src_rse_id, dst_rse_id, ranking=10)

    did = did_factory.random_file_did()
    file = {'scope': did['scope'], 'name': did['name'], 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    add_replicas(rse_id=src_rse_id, files=[file], account=root_account)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    requests_by_id = list_transfer_requests_and_source_replicas(rses=[src_rse_id, dst_rse_id])
    requests, *_ = build_transfer_paths(topology=Topology.create_from_config(), requests_with_sources=requests_by_id.values())
    request_id, [transfer_path] = next(iter(requests.items()))

    transfer_path[0].rws.request_id = generate_uuid()
    to_submit, *_ = assign_paths_to_transfertool_and_create_hops(requests)
    assert not to_submit
