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

import itertools
from datetime import datetime, timedelta
from random import randint
from unittest.mock import patch
from sqlalchemy import delete

from rucio.common.exception import RequestNotFound
from rucio.core import distance as distance_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.core import replica as replica_core
from rucio.core import rule as rule_core
from rucio.core import config as core_config
from rucio.daemons.conveyor.submitter import submitter
from rucio.daemons.reaper.reaper import reaper
from rucio.db.sqla.models import Request, Source
from rucio.db.sqla.constants import RequestState
from rucio.db.sqla.session import read_session, transactional_session
from tests.ruciopytest import NoParallelGroups


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
def test_request_submitted_in_order(rse_factory, did_factory, root_account):

    src_rses = [rse_factory.make_posix_rse() for _ in range(2)]
    dst_rses = [rse_factory.make_posix_rse() for _ in range(3)]
    for _, src_rse_id in src_rses:
        for _, dst_rse_id in dst_rses:
            distance_core.add_distance(src_rse_id=src_rse_id, dest_rse_id=dst_rse_id, distance=10)
            distance_core.add_distance(src_rse_id=dst_rse_id, dest_rse_id=src_rse_id, distance=10)

    # Create a certain number of files on source RSEs with replication rules towards random destination RSEs
    nb_files = 15
    dids = []
    requests = []
    src_rses_iterator = itertools.cycle(src_rses)
    dst_rses_iterator = itertools.cycle(dst_rses)
    for _ in range(nb_files):
        src_rse_name, src_rse_id = next(src_rses_iterator)
        dst_rse_name, dst_rse_id = next(dst_rses_iterator)
        did = did_factory.upload_test_file(rse_name=src_rse_name)
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        requests.append(request_core.get_request_by_did(rse_id=dst_rse_id, **did))
        dids.append(did)

    # Forge request creation time to a random moment in the past hour
    @transactional_session
    def _forge_requests_creation_time(*, session=None):
        base_time = datetime.utcnow().replace(microsecond=0, minute=0) - timedelta(hours=1)
        assigned_times = set()
        for request in requests:
            request_creation_time = None
            while not request_creation_time or request_creation_time in assigned_times:
                # Ensure uniqueness to avoid multiple valid submission orders and make tests deterministic with simple sorting techniques
                request_creation_time = base_time + timedelta(minutes=randint(0, 3600))
            assigned_times.add(request_creation_time)
            session.query(Request).filter(Request.id == request['id']).update({'created_at': request_creation_time})
            request['created_at'] = request_creation_time

    _forge_requests_creation_time()
    requests = sorted(requests, key=lambda r: r['created_at'])

    for request in requests:
        assert request_core.get_request(request_id=request['id'])['state'] == RequestState.QUEUED

    requests_id_in_submission_order = []
    with patch('rucio.transfertool.mock.MockTransfertool.submit') as mock_transfertool_submit:
        # Record the order of requests passed to MockTranfertool.submit()
        mock_transfertool_submit.side_effect = lambda transfers, job_params, timeout: requests_id_in_submission_order.extend([t.rws.request_id for t in transfers])

        submitter(once=True, rses=[{'id': rse_id} for _, rse_id in dst_rses], partition_wait_time=None, transfertools=['mock'], transfertype='single', filter_transfertool=None)

    for request in requests:
        assert request_core.get_request(request_id=request['id'])['state'] == RequestState.SUBMITTED

    # Requests must be submitted in the order of their creation
    assert requests_id_in_submission_order == [r['id'] for r in requests]


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
@pytest.mark.parametrize("core_config_mock", [
    # Run test twice: with, and without, temp tables
    {
        "table_content": [
            ('transfers', 'multihop_rse_expression', '*'),
        ]
    }
], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_multihop_sources_created(rse_factory, did_factory, root_account, core_config_mock, caches_mock, metrics_mock):
    """
    Ensure that multihop transfers are handled and intermediate request correctly created
    """
    src_rse_name, src_rse_id = rse_factory.make_posix_rse()
    _, jump_rse1_id = rse_factory.make_posix_rse()
    _, jump_rse2_id = rse_factory.make_posix_rse()
    _, jump_rse3_id = rse_factory.make_posix_rse()
    dst_rse_name, dst_rse_id = rse_factory.make_posix_rse()

    jump_rses = [jump_rse1_id, jump_rse2_id, jump_rse3_id]
    all_rses = jump_rses + [src_rse_id, dst_rse_id]

    rse_tombstone_delay = 3600
    rse_multihop_tombstone_delay = 12 * 3600
    default_multihop_tombstone_delay = 24 * 3600

    # if both attributes are set, the multihop one will take precedence
    rse_core.add_rse_attribute(jump_rse1_id, 'tombstone_delay', rse_tombstone_delay)
    rse_core.add_rse_attribute(jump_rse1_id, 'multihop_tombstone_delay', rse_multihop_tombstone_delay)

    # if multihop delay not set, it's the default multihop takes precedence. Not normal tombstone delay.
    rse_core.add_rse_attribute(jump_rse2_id, 'tombstone_delay', rse_tombstone_delay)
    core_config.set(section='transfers', option='multihop_tombstone_delay', value=default_multihop_tombstone_delay)

    # if multihop delay is set to 0, the replica will have no tombstone
    rse_core.add_rse_attribute(jump_rse3_id, 'multihop_tombstone_delay', 0)

    distance_core.add_distance(src_rse_id, jump_rse1_id, distance=10)
    distance_core.add_distance(jump_rse1_id, jump_rse2_id, distance=10)
    distance_core.add_distance(jump_rse2_id, jump_rse3_id, distance=10)
    distance_core.add_distance(jump_rse3_id, dst_rse_id, distance=10)

    did = did_factory.upload_test_file(src_rse_name)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertools=['mock'], transfertype='single', filter_transfertool=None)

    # Ensure that each intermediate request was correctly created
    request = request_core.get_request_by_did(rse_id=jump_rse1_id, **did)
    assert request
    assert request['source_rse_id'] == src_rse_id
    request = request_core.get_request_by_did(rse_id=jump_rse2_id, **did)
    assert request
    assert request['source_rse_id'] == jump_rse1_id
    request = request_core.get_request_by_did(rse_id=jump_rse3_id, **did)
    assert request
    assert request['source_rse_id'] == jump_rse2_id
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request
    assert request['source_rse_id'] == jump_rse3_id

    @read_session
    def __number_sources(rse_id, scope, name, *, session=None):
        return session.query(Source). \
            filter(Source.rse_id == rse_id). \
            filter(Source.scope == scope). \
            filter(Source.name == name). \
            count()

    # Ensure that sources where created for transfers
    for rse_id in [src_rse_id, jump_rse1_id, jump_rse2_id]:
        assert __number_sources(rse_id, **did) == 2
    assert __number_sources(jump_rse3_id, **did) == 1

    # Ensure the tombstone is correctly set on intermediate replicas
    expected_tombstone = datetime.utcnow() + timedelta(seconds=rse_multihop_tombstone_delay)
    replica = replica_core.get_replica(jump_rse1_id, **did)
    assert expected_tombstone - timedelta(minutes=5) < replica['tombstone'] < expected_tombstone + timedelta(minutes=5)

    expected_tombstone = datetime.utcnow() + timedelta(seconds=default_multihop_tombstone_delay)
    replica = replica_core.get_replica(jump_rse2_id, **did)
    assert expected_tombstone - timedelta(minutes=5) < replica['tombstone'] < expected_tombstone + timedelta(minutes=5)

    replica = replica_core.get_replica(jump_rse3_id, **did)
    assert replica['tombstone'] is None

    # Ensure that prometheus metrics were correctly registered. Only one submission, mock transfertool groups everything into one job.
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_common_submit_transfer_total') == 1


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
]}], indirect=True)
def test_source_avoid_deletion(caches_mock, rse_factory, did_factory, root_account):
    """ Test that sources on a file block it from deletion """

    reaper_region, _ = caches_mock
    src_rse1, src_rse1_id = rse_factory.make_mock_rse()
    src_rse2, src_rse2_id = rse_factory.make_mock_rse()
    dst_rse, dst_rse_id = rse_factory.make_mock_rse()
    all_rses = [src_rse1_id, src_rse2_id, dst_rse_id]
    any_source = f'{src_rse1}|{src_rse2}'

    for rse_id in [src_rse1_id, src_rse2_id]:
        rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=1)
        rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=1, free=0)
    distance_core.add_distance(src_rse1_id, dst_rse_id, distance=20)
    distance_core.add_distance(src_rse2_id, dst_rse_id, distance=10)

    # Upload a test file to both rses without registering
    did = did_factory.random_file_did()

    # Register replica on one source RSE
    replica_core.add_replica(rse_id=src_rse1_id, account=root_account, bytes_=1, tombstone=datetime(year=1970, month=1, day=1), **did)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    # Reaper will not delete a file which only has one replica if there is any pending transfer for it
    reaper_region.invalidate()
    reaper(once=True, rses=[], include_rses=any_source, exclude_rses=None)
    replica = next(iter(replica_core.list_replicas(dids=[did], rse_expression=any_source)))
    assert len(replica['pfns']) == 1

    # Register replica on second source rse
    replica_core.add_replica(rse_id=src_rse2_id, account=root_account, bytes_=1, tombstone=datetime(year=1970, month=1, day=1), **did)
    replica = next(iter(replica_core.list_replicas(dids=[did], rse_expression=any_source)))
    assert len(replica['pfns']) == 2

    # Submit the transfer. This will create the sources.
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertools=['mock'], transfertype='single', filter_transfertool=None)

    # None of the replicas will be removed. They are protected by an entry in the sources table
    reaper_region.invalidate()
    reaper(once=True, rses=[], include_rses=any_source, exclude_rses=None)
    replica = next(iter(replica_core.list_replicas(dids=[did], rse_expression=any_source)))
    assert len(replica['pfns']) == 2

    @transactional_session
    def __delete_sources(rse_id, scope, name, *, session=None):
        session.execute(
            delete(Source).where(Source.rse_id == rse_id,
                                 Source.scope == scope,
                                 Source.name == name))

    # Deletion succeeds for one replica (second still protected by existing request)
    __delete_sources(src_rse1_id, **did)
    __delete_sources(src_rse2_id, **did)
    reaper_region.invalidate()
    reaper(once=True, rses=[], include_rses=any_source, exclude_rses=None)
    replica = next(iter(replica_core.list_replicas(dids=[did], rse_expression=any_source)))
    assert len(replica['pfns']) == 1


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
]}], indirect=True)
def test_ignore_availability(rse_factory, did_factory, root_account, caches_mock):

    def __setup_test():
        src_rse, src_rse_id = rse_factory.make_posix_rse()
        dst_rse, dst_rse_id = rse_factory.make_posix_rse()

        distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
        did = did_factory.upload_test_file(src_rse)
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        rse_core.update_rse(src_rse_id, {'availability_read': False})

        return src_rse_id, dst_rse_id, did

    src_rse_id, dst_rse_id, did = __setup_test()
    submitter(once=True, rses=[{'id': rse_id} for rse_id in (src_rse_id, dst_rse_id)], partition_wait_time=None, transfertools=['mock'], transfertype='single')
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.NO_SOURCES

    src_rse_id, dst_rse_id, did = __setup_test()
    submitter(once=True, rses=[{'id': rse_id} for rse_id in (src_rse_id, dst_rse_id)], partition_wait_time=None, transfertools=['mock'], transfertype='single', ignore_availability=True)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.SUBMITTED
    assert request['transfertool'] == 'mock'


@pytest.mark.noparallel(reason="multiple submitters cannot be run in parallel due to partial job assignment by hash")
@pytest.mark.parametrize("file_config_mock", [
    {"overrides": [('transfers', 'source_ranking_strategies', 'SkipSchemeMissmatch,PathDistance')]},
    {"overrides": [('transfers', 'source_ranking_strategies', 'PathDistance')]}
], indirect=True)
def test_scheme_missmatch(rse_factory, did_factory, root_account, file_config_mock):
    """
    Ensure that the requests are marked MISSMATCH_SCHEME when there is a path, but with wrong schemes.
    """
    src_rse, src_rse_id = rse_factory.make_posix_rse()
    dst_rse, dst_rse_id = rse_factory.make_mock_rse()

    distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)

    did = did_factory.upload_test_file(src_rse)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    submitter(once=True, rses=[{'id': rse_id} for rse_id in (src_rse_id, dst_rse_id)], partition_wait_time=None, transfertools=['mock'], transfertype='single')

    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    if 'SkipSchemeMissmatch' in file_config_mock.get('transfers', 'source_ranking_strategies'):
        assert request['state'] == RequestState.MISMATCH_SCHEME
    else:
        assert request['state'] == RequestState.NO_SOURCES


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
def test_globus(rse_factory, did_factory, root_account):
    """
    Test bulk submissions with globus transfertool.
    Rely on mocks, because we don't contact a real globus server in tests
    """
    # +------+    +------+
    # |      |    |      |
    # | RSE1 +--->| RSE2 |
    # |      |    |      |
    # +------+    +------+
    #
    # +------+    +------+
    # |      |    |      |
    # | RSE3 +--->| RSE4 |
    # |      |    |      |
    # +------+    +------+
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()
    rse3, rse3_id = rse_factory.make_posix_rse()
    rse4, rse4_id = rse_factory.make_posix_rse()
    all_rses = [rse1_id, rse2_id, rse3_id, rse4_id]

    distance_core.add_distance(rse1_id, rse2_id, distance=10)
    distance_core.add_distance(rse3_id, rse4_id, distance=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'globus_endpoint_id', rse_id)

    # Single submission
    did1 = did_factory.upload_test_file(rse1)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    did2 = did_factory.upload_test_file(rse3)
    rule_core.add_rule(dids=[did2], account=root_account, copies=1, rse_expression=rse4, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    with patch('rucio.transfertool.globus.bulk_submit_xfer') as mock_bulk_submit:
        mock_bulk_submit.return_value = 0
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertools=['globus'], transfertype='single', filter_transfertool=None)
        # Called separately for each job
        assert len(mock_bulk_submit.call_args_list) == 2
        (submitjob,), _kwargs = mock_bulk_submit.call_args_list[0]
        assert len(submitjob) == 1

    # Bulk submission
    did1 = did_factory.upload_test_file(rse1)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    did2 = did_factory.upload_test_file(rse3)
    rule_core.add_rule(dids=[did2], account=root_account, copies=1, rse_expression=rse4, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    with patch('rucio.transfertool.globus.bulk_submit_xfer') as mock_bulk_submit:
        mock_bulk_submit.return_value = 0
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertools=['globus'], transfertype='bulk', filter_transfertool=None)

        mock_bulk_submit.assert_called_once()
        (submitjob,), _kwargs = mock_bulk_submit.call_args_list[0]

        # both jobs were grouped together and submitted in one call
        assert len(submitjob) == 2

        job_did1 = next(iter(filter(lambda job: did1['name'] in job['sources'][0], submitjob)))
        assert len(job_did1['sources']) == 1
        assert len(job_did1['destinations']) == 1
        assert job_did1['metadata']['src_rse'] == rse1
        assert job_did1['metadata']['dst_rse'] == rse2
        assert job_did1['metadata']['name'] == did1['name']
        assert job_did1['metadata']['source_globus_endpoint_id'] == rse1_id
        assert job_did1['metadata']['dest_globus_endpoint_id'] == rse2_id

        job_did2 = next(iter(filter(lambda job: did2['name'] in job['sources'][0], submitjob)))
        assert len(job_did2['sources']) == 1
        assert len(job_did2['destinations']) == 1
        assert job_did2['metadata']['src_rse'] == rse3
        assert job_did2['metadata']['dst_rse'] == rse4
        assert job_did2['metadata']['name'] == did2['name']
    request = request_core.get_request_by_did(rse_id=rse2_id, **did1)
    assert request['state'] == RequestState.SUBMITTED
    assert request['transfertool'] == 'globus'
    request = request_core.get_request_by_did(rse_id=rse4_id, **did2)
    assert request['state'] == RequestState.SUBMITTED
    assert request['transfertool'] == 'globus'


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('transfers', 'hop_penalty', '5'),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
]}], indirect=True)
def test_hop_penalty(rse_factory, did_factory, root_account, file_config_mock, caches_mock):
    """
    Test that both global hop_penalty and the per-rse one are correctly taken into consideration
    """
    # +------+    +------+    +------+
    # |      |    |  5   |    |      |
    # | RSE1 +--->| RSE2 +--->| RSE3 |
    # |      |    |      |    |      |
    # +------+    +------+    +--^---+
    #                            |
    # +------+    +------+       |
    # |      |    |  20  |       |
    # | RSE4 +--->| RSE5 +-------+
    # |      |    |      |
    # +------+    +------+
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()
    rse3, rse3_id = rse_factory.make_posix_rse()
    rse4, rse4_id = rse_factory.make_posix_rse()
    rse5, rse5_id = rse_factory.make_posix_rse()
    all_rses = [rse1_id, rse2_id, rse3_id, rse4_id, rse5_id]

    distance_core.add_distance(rse1_id, rse2_id, distance=10)
    distance_core.add_distance(rse2_id, rse3_id, distance=10)
    distance_core.add_distance(rse4_id, rse5_id, distance=10)
    distance_core.add_distance(rse5_id, rse3_id, distance=10)

    rse_core.add_rse_attribute(rse2_id, 'available_for_multihop', True)
    rse_core.add_rse_attribute(rse5_id, 'available_for_multihop', True)
    rse_core.add_rse_attribute(rse5_id, 'hop_penalty', 20)

    did = did_factory.random_file_did()
    replica_core.add_replica(rse_id=rse1_id, account=root_account, bytes_=1, **did)
    replica_core.add_replica(rse_id=rse4_id, account=root_account, bytes_=1, **did)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=rse3, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertools=['mock'], transfertype='single', ignore_availability=True)

    # Ensure the path was created through the correct middle hop
    request_core.get_request_by_did(rse_id=rse2_id, **did)
    with pytest.raises(RequestNotFound):
        request_core.get_request_by_did(rse_id=rse5_id, **did)
