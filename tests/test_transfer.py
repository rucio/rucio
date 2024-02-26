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
import datetime

from rucio.common.exception import NoDistance
from rucio.core.distance import add_distance
from rucio.core.replica import add_replicas
from rucio.core.request import list_and_mark_transfer_requests_and_source_replicas
from rucio.core.transfer import build_transfer_paths, ProtocolFactory
from rucio.core.topology import get_hops, Topology
from rucio.core import rule as rule_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType, RequestState
from rucio.db.sqla.session import get_session
from rucio.common.utils import generate_uuid
from rucio.daemons.conveyor.common import assign_paths_to_transfertool_and_create_hops, pick_and_prepare_submission_path


def _prepare_submission(rses):
    topology = Topology().configure_multihop()
    requests_with_sources = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=rses)
    pick_and_prepare_submission_path(requests_with_sources, topology=topology, protocol_factory=ProtocolFactory(), default_tombstone_delay=0)


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

    add_distance(rse1_id, rse3_id, distance=40)
    add_distance(rse1_id, rse2_id, distance=10)

    add_distance(rse2_id, rse1_id, distance=10)
    add_distance(rse2_id, rse4_id, distance=10)

    add_distance(rse3_id, rse1_id, distance=40)
    add_distance(rse3_id, rse4_id, distance=10)
    add_distance(rse3_id, rse5_id, distance=50)

    add_distance(rse4_id, rse2_id, distance=10)
    add_distance(rse4_id, rse5_id, distance=10)

    add_distance(rse5_id, rse3_id, distance=50)
    add_distance(rse5_id, rse4_id, distance=10)
    add_distance(rse5_id, rse6_id, distance=20)

    # There must be no paths between an isolated node and other nodes; be it with multipath enabled or disabled
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse0_id, dest_rse_id=rse1_id)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse1_id, dest_rse_id=rse0_id)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse0_id, dest_rse_id=rse1_id, multihop_rse_ids=all_rses)
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse1_id, dest_rse_id=rse0_id, multihop_rse_ids=all_rses)

    # A single hop path must be found between two directly connected RSE
    [hop] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse2_id)
    assert hop['source_rse'].id == rse1_id
    assert hop['dest_rse'].id == rse2_id

    # No path will be found if there is no direct connection and "include_multihop" is not set
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id)

    # No multihop rses given, multihop disabled
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id, multihop_rse_ids=set())

    # The shortest multihop path will be computed
    [hop1, hop2] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse2_id, multihop_rse_ids=all_rses)
    assert hop1['source_rse'].id == rse3_id
    assert hop1['dest_rse'].id == rse4_id
    assert hop2['source_rse'].id == rse4_id
    assert hop2['dest_rse'].id == rse2_id

    # multihop_rses doesn't contain the RSE needed for the shortest path. Return a longer path
    [hop1, hop2] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse4_id, multihop_rse_ids={rse3_id})
    assert hop1['source_rse'].id == rse1_id
    assert hop1['dest_rse'].id == rse3_id
    assert hop2['source_rse'].id == rse3_id
    assert hop2['dest_rse'].id == rse4_id

    # A link with cost only in one direction will not be used in the opposite direction
    with pytest.raises(NoDistance):
        get_hops(source_rse_id=rse6_id, dest_rse_id=rse5_id, multihop_rse_ids=all_rses)
    [hop1, hop2] = get_hops(source_rse_id=rse4_id, dest_rse_id=rse3_id, multihop_rse_ids=all_rses)
    assert hop1['source_rse'].id == rse4_id
    assert hop2['source_rse'].id == rse5_id
    assert hop2['dest_rse'].id == rse3_id

    # A longer path is preferred over a shorter one with high intermediate cost
    [hop1, hop2, hop3] = get_hops(source_rse_id=rse3_id, dest_rse_id=rse6_id, multihop_rse_ids=all_rses)
    assert hop1['source_rse'].id == rse3_id
    assert hop2['source_rse'].id == rse4_id
    assert hop3['source_rse'].id == rse5_id
    assert hop3['dest_rse'].id == rse6_id

    # A link with no cost is ignored. Both for direct connection and multihop paths
    [hop1, hop2, hop3] = get_hops(source_rse_id=rse2_id, dest_rse_id=rse6_id, multihop_rse_ids=all_rses)
    assert hop1['source_rse'].id == rse2_id
    assert hop2['source_rse'].id == rse4_id
    assert hop3['source_rse'].id == rse5_id
    assert hop3['dest_rse'].id == rse6_id
    [hop1, hop2, hop3, hop4] = get_hops(source_rse_id=rse1_id, dest_rse_id=rse6_id, multihop_rse_ids=all_rses)
    assert hop1['source_rse'].id == rse1_id
    assert hop2['source_rse'].id == rse2_id
    assert hop3['source_rse'].id == rse4_id
    assert hop4['source_rse'].id == rse5_id
    assert hop4['dest_rse'].id == rse6_id


def test_disk_vs_tape_priority(rse_factory, root_account, mock_scope, file_config_mock):
    tape1_rse_name, tape1_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.TAPE)
    tape2_rse_name, tape2_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.TAPE)
    disk1_rse_name, disk1_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.DISK)
    disk2_rse_name, disk2_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.DISK)
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    source_rses = [tape1_rse_id, tape2_rse_id, disk1_rse_id, disk2_rse_id]
    all_rses = source_rses + [dst_rse_id]
    add_distance(disk1_rse_id, dst_rse_id, distance=15)
    add_distance(disk2_rse_id, dst_rse_id, distance=10)
    add_distance(tape1_rse_id, dst_rse_id, distance=15)
    add_distance(tape2_rse_id, dst_rse_id, distance=10)

    # add same file to all source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in source_rses:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    topology = Topology().configure_multihop()
    requests = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=all_rses)
    assert len(requests) == 1
    [rws] = requests.values()
    disk1_source = next(iter(s for s in rws.sources if s.rse.id == disk1_rse_id))
    disk2_source = next(iter(s for s in rws.sources if s.rse.id == disk2_rse_id))
    tape2_source = next(iter(s for s in rws.sources if s.rse.id == tape2_rse_id))

    # On equal priority and distance, disk should be preferred over tape. Both disk sources will be returned
    [[_, [transfer]]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                         requests_with_sources=requests).items()
    assert len(transfer[0].sources) == 2
    assert transfer[0].sources[0].rse.name in (disk1_rse_name, disk2_rse_name)

    # Change the rating of the disk RSEs. Disk still preferred, because it must fail twice before tape is tried
    disk1_source.ranking = -1
    disk2_source.ranking = -1
    [[_, [transfer]]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                         requests_with_sources=requests).items()
    assert len(transfer[0].sources) == 2
    assert transfer[0].sources[0].rse.name in (disk1_rse_name, disk2_rse_name)

    # Change the rating of the disk RSEs again. Tape RSEs must now be preferred.
    # Multiple tape sources are not allowed. Only one tape RSE source must be returned.
    disk1_source.ranking = -2
    disk2_source.ranking = -2
    [[_, transfers]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                        requests_with_sources=requests).items()
    assert len(transfers) == 1
    transfer = transfers[0]
    assert len(transfer[0].sources) == 1
    assert transfer[0].sources[0].rse.name in (tape1_rse_name, tape2_rse_name)

    # On equal source ranking, but different distance; the smaller distance is preferred
    [[_, [transfer]]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                         requests_with_sources=requests).items()
    assert len(transfer[0].sources) == 1
    assert transfer[0].sources[0].rse.name == tape2_rse_name

    # On different source ranking, the bigger ranking is preferred
    tape2_source.ranking = -1
    [[_, [transfer]]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                         requests_with_sources=requests).items()
    assert len(transfer[0].sources) == 1
    assert transfer[0].sources[0].rse.name == tape1_rse_name


@pytest.mark.parametrize("file_config_mock", [
    {"overrides": [('transfers', 'source_ranking_strategies', 'PathDistance')]},
    {"overrides": [('transfers', 'source_ranking_strategies', 'PreferDiskOverTape,PathDistance')]}
], indirect=True)
def test_disk_vs_tape_with_custom_strategy(rse_factory, root_account, mock_scope, file_config_mock):
    """
    Disk RSEs are preferred over tape only if the PreferDiskOverTape strategy is set.
    """
    disk_rse_name, disk_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.DISK)
    tape_rse_name, tape_rse_id = rse_factory.make_posix_rse(rse_type=RSEType.TAPE)
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    all_rses = [tape_rse_id, disk_rse_id, dst_rse_id]
    add_distance(disk_rse_id, dst_rse_id, distance=20)
    add_distance(tape_rse_id, dst_rse_id, distance=10)

    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in [tape_rse_id, disk_rse_id]:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    topology = Topology().configure_multihop()
    requests = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=all_rses)

    [[_, [transfer]]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                         requests_with_sources=requests).items()
    if 'PreferDiskOverTape' in file_config_mock.get('transfers', 'source_ranking_strategies'):
        assert transfer[0].src.rse.name == disk_rse_name
    else:
        assert transfer[0].src.rse.name == tape_rse_name


@pytest.mark.parametrize("file_config_mock", [
    {"overrides": [('transfers', 'source_ranking_strategies', 'PathDistance')]},
    {"overrides": [('transfers', 'source_ranking_strategies', 'FailureRate,PathDistance')]}
], indirect=True)
def test_failure_rate_with_custom_strategy(rse_factory, root_account, mock_scope, file_config_mock):
    """
    RSE with lower failure rate is preferred if the FailureRate strategy is set.
    """
    low_failure_rse_name, low_failure_rse_id = rse_factory.make_posix_rse()
    high_failure_rse_name, high_failure_rse_id = rse_factory.make_posix_rse()
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    all_rses = [low_failure_rse_id, high_failure_rse_id, dst_rse_id]
    add_distance(low_failure_rse_id, dst_rse_id, distance=20)
    add_distance(high_failure_rse_id, dst_rse_id, distance=10)

    # add mock data to TransferStats table
    db_session = get_session()

    # ensure that the failure rate for a source RSE is summed across all activities and destinations,
    # low failure RSE has failure rate of 0.25
    # high failure RSE has failure rate of 0.5
    low_failure_transfer_activity_1 = models.TransferStats(
        resolution=datetime.timedelta(minutes=5).total_seconds(),
        timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=30),
        dest_rse_id=high_failure_rse_id,
        src_rse_id=low_failure_rse_id,
        activity="test activity 1",
        files_done=2,
        bytes_done=12345,
        files_failed=0
    )
    low_failure_transfer_activity_2 = models.TransferStats(
        resolution=datetime.timedelta(minutes=5).total_seconds(),
        timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=30),
        dest_rse_id=dst_rse_id,
        src_rse_id=low_failure_rse_id,
        activity="test activity 2",
        files_done=1,
        bytes_done=12345,
        files_failed=1
    )
    high_failure_transfer_activity = models.TransferStats(
        resolution=datetime.timedelta(minutes=5).total_seconds(),
        timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=30),
        dest_rse_id=dst_rse_id,
        src_rse_id=high_failure_rse_id,
        activity="test activity 1",
        files_done=1,
        bytes_done=12345,
        files_failed=1
    )

    low_failure_transfer_activity_1.save(session=db_session)
    low_failure_transfer_activity_2.save(session=db_session)
    high_failure_transfer_activity.save(session=db_session)

    db_session.commit()
    db_session.expunge(low_failure_transfer_activity_1)
    db_session.expunge(low_failure_transfer_activity_2)
    db_session.expunge(high_failure_transfer_activity)

    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in [low_failure_rse_id, high_failure_rse_id]:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    topology = Topology().configure_multihop()
    requests = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=all_rses)

    [[_, [transfer]]] = pick_and_prepare_submission_path(topology=topology, protocol_factory=ProtocolFactory(),
                                                         requests_with_sources=requests).items()
    if 'FailureRate' in file_config_mock.get('transfers', 'source_ranking_strategies'):
        assert transfer[0].src.rse.name == low_failure_rse_name
    else:
        assert transfer[0].src.rse.name == high_failure_rse_name


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
]}], indirect=True)
def test_multihop_requests_created(rse_factory, did_factory, root_account, caches_mock):
    """
    Ensure that multihop transfers are handled and intermediate request correctly created
    """
    rs0_name, src_rse_id = rse_factory.make_posix_rse()
    _, intermediate_rse_id = rse_factory.make_posix_rse()
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()
    rse_core.add_rse_attribute(intermediate_rse_id, 'available_for_multihop', True)

    add_distance(src_rse_id, intermediate_rse_id, distance=10)
    add_distance(intermediate_rse_id, dst_rse_id, distance=10)

    did = did_factory.upload_test_file(rs0_name)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    _prepare_submission(rses=[src_rse_id, dst_rse_id])
    # the intermediate request was correctly created
    assert request_core.get_request_by_did(rse_id=intermediate_rse_id, **did)


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
]}], indirect=True)
def test_multihop_concurrent_submitters(rse_factory, did_factory, root_account, caches_mock):
    """
    Ensure that multiple concurrent submitters on the same multi-hop don't result in an undesired database state
    """
    src_rse, src_rse_id = rse_factory.make_posix_rse()
    jump_rse, jump_rse_id = rse_factory.make_posix_rse()
    dst_rse, dst_rse_id = rse_factory.make_posix_rse()
    rse_core.add_rse_attribute(jump_rse_id, 'available_for_multihop', True)

    add_distance(src_rse_id, jump_rse_id, distance=10)
    add_distance(jump_rse_id, dst_rse_id, distance=10)

    did = did_factory.upload_test_file(src_rse)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    nb_threads = 9
    nb_executions = 18
    with ThreadPoolExecutor(max_workers=nb_threads) as executor:
        futures = [executor.submit(_prepare_submission, rses=rse_factory.created_rses) for _ in range(nb_executions)]
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


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
]}], indirect=True)
def test_singlehop_vs_multihop_priority(rse_factory, root_account, mock_scope, caches_mock):
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
    all_rses = [rse0_id, rse1_id, rse2_id, rse3_id, rse4_id]

    add_distance(rse0_id, rse1_id, distance=10)
    add_distance(rse1_id, rse3_id, distance=10)
    add_distance(rse2_id, rse3_id, distance=30)
    add_distance(rse4_id, rse3_id, distance=200)
    rse_core.add_rse_attribute(rse1_id, 'available_for_multihop', True)

    topology = Topology(rse_ids=all_rses).configure_multihop()

    # add same file to two source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in [rse0_id, rse2_id]:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=rse3_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    # add same file to two source RSEs
    file = {'scope': mock_scope, 'name': 'lfn.' + generate_uuid(), 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    did = {'scope': file['scope'], 'name': file['name']}
    for rse_id in [rse0_id, rse4_id]:
        add_replicas(rse_id=rse_id, files=[file], account=root_account)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=rse3_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    requests = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=all_rses)
    assert len(requests) == 2
    rws_sh_prio = next(iter(rws for rws in requests.values() if rse2_id in (s.rse.id for s in rws.sources)))
    rws_mh_prio = next(iter(rws for rws in requests.values() if rse4_id in (s.rse.id for s in rws.sources)))

    # The singlehop must be prioritized
    paths, *_ = build_transfer_paths(topology=topology, protocol_factory=ProtocolFactory(),
                                     requests_with_sources=[rws_sh_prio])
    [[_, candidate_paths]] = paths.items()
    assert len(candidate_paths) == 2
    assert len(candidate_paths[0]) == 1
    assert len(candidate_paths[1]) == 2
    assert candidate_paths[0][0].src.rse.id == rse2_id
    assert candidate_paths[0][0].dst.rse.id == rse3_id

    # The multihop must be prioritized
    paths, *_ = build_transfer_paths(topology=topology, protocol_factory=ProtocolFactory(),
                                     requests_with_sources=[rws_mh_prio])
    [[_, candidate_paths]] = paths.items()
    assert len(candidate_paths) == 2
    assert len(candidate_paths[0]) == 2
    assert len(candidate_paths[1]) == 1
    assert candidate_paths[0][0].src.rse.id == rse0_id
    assert candidate_paths[0][0].dst.rse.id == rse1_id
    assert candidate_paths[0][1].src.rse.id == rse1_id
    assert candidate_paths[0][1].dst.rse.id == rse3_id


def test_fk_error_on_source_creation(rse_factory, did_factory, root_account):
    """
    verify that ensure_db_sources correctly handles foreign key errors while creating sources
    """

    if get_session().bind.dialect.name == 'sqlite':
        pytest.skip('Will not run on sqlite')

    src_rse, src_rse_id = rse_factory.make_mock_rse()
    dst_rse, dst_rse_id = rse_factory.make_mock_rse()
    all_rses = [src_rse_id, dst_rse_id]
    add_distance(src_rse_id, dst_rse_id, distance=10)

    topology = Topology(rse_ids=all_rses).configure_multihop()
    did = did_factory.random_file_did()
    file = {'scope': did['scope'], 'name': did['name'], 'type': 'FILE', 'bytes': 1, 'adler32': 'beefdead'}
    add_replicas(rse_id=src_rse_id, files=[file], account=root_account)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    requests_by_id = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=[src_rse_id, dst_rse_id])
    requests, *_ = build_transfer_paths(topology=topology, protocol_factory=ProtocolFactory(), requests_with_sources=requests_by_id.values())
    request_id, [transfer_path] = next(iter(requests.items()))

    transfer_path[0].rws.request_id = generate_uuid()
    to_submit, *_ = assign_paths_to_transfertool_and_create_hops(requests, default_tombstone_delay=0)
    assert not to_submit
