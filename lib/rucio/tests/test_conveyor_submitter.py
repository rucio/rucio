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

import itertools
from datetime import datetime, timedelta
from random import randint
from unittest.mock import patch

from rucio.core import distance as distance_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.core import replica as replica_core
from rucio.core import rule as rule_core
from rucio.core import config as core_config
from rucio.daemons.conveyor.submitter import submitter
from rucio.db.sqla.models import Request, Source
from rucio.db.sqla.constants import RequestState
from rucio.db.sqla.session import read_session, transactional_session


@pytest.mark.noparallel(reason="multiple submitters cannot be run in parallel due to partial job assignment by hash")
def test_request_submitted_in_order(rse_factory, did_factory, root_account):

    src_rses = [rse_factory.make_posix_rse() for _ in range(2)]
    dst_rses = [rse_factory.make_posix_rse() for _ in range(3)]
    for _, src_rse_id in src_rses:
        for _, dst_rse_id in dst_rses:
            distance_core.add_distance(src_rse_id=src_rse_id, dest_rse_id=dst_rse_id, ranking=10)
            distance_core.add_distance(src_rse_id=dst_rse_id, dest_rse_id=src_rse_id, ranking=10)

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
    def _forge_requests_creation_time(session=None):
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
        mock_transfertool_submit.side_effect = lambda jobs, _: requests_id_in_submission_order.extend([j['metadata']['request_id'] for j in jobs])

        submitter(once=True, rses=[{'id': rse_id} for _, rse_id in dst_rses], partition_wait_time=None, transfertool='mock', transfertype='single', filter_transfertool=None)

    for request in requests:
        assert request_core.get_request(request_id=request['id'])['state'] == RequestState.SUBMITTED

    # Requests must be submitted in the order of their creation
    assert requests_id_in_submission_order == [r['id'] for r in requests]


@pytest.mark.noparallel(reason="multiple submitters cannot be run in parallel due to partial job assignment by hash")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
]}], indirect=True)
def test_multihop_sources_created(rse_factory, did_factory, root_account, core_config_mock, caches_mock):
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

    for rse_id in jump_rses:
        rse_core.add_rse_attribute(rse_id, 'available_for_multihop', True)

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

    distance_core.add_distance(src_rse_id, jump_rse1_id, ranking=10)
    distance_core.add_distance(jump_rse1_id, jump_rse2_id, ranking=10)
    distance_core.add_distance(jump_rse2_id, jump_rse3_id, ranking=10)
    distance_core.add_distance(jump_rse3_id, dst_rse_id, ranking=10)

    did = did_factory.upload_test_file(src_rse_name)
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertool='mock', transfertype='single', filter_transfertool=None)

    # Ensure that each intermediate request was correctly created
    for rse_id in jump_rses:
        assert request_core.get_request_by_did(rse_id=rse_id, **did)

    @read_session
    def __ensure_source_exists(rse_id, scope, name, session=None):
        return session.query(Source). \
            filter(Source.rse_id == rse_id). \
            filter(Source.scope == scope). \
            filter(Source.name == name). \
            one()

    # Ensure that sources where created for transfers
    for rse_id in jump_rses + [src_rse_id]:
        __ensure_source_exists(rse_id, **did)

    # Ensure the tombstone is correctly set on intermediate replicas
    expected_tombstone = datetime.utcnow() + timedelta(seconds=rse_multihop_tombstone_delay)
    replica = replica_core.get_replica(jump_rse1_id, **did)
    assert expected_tombstone - timedelta(minutes=5) < replica['tombstone'] < expected_tombstone + timedelta(minutes=5)

    expected_tombstone = datetime.utcnow() + timedelta(seconds=default_multihop_tombstone_delay)
    replica = replica_core.get_replica(jump_rse2_id, **did)
    assert expected_tombstone - timedelta(minutes=5) < replica['tombstone'] < expected_tombstone + timedelta(minutes=5)

    replica = replica_core.get_replica(jump_rse3_id, **did)
    assert replica['tombstone'] is None


@pytest.mark.noparallel(reason="multiple submitters cannot be run in parallel due to partial job assignment by hash")
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

    distance_core.add_distance(rse1_id, rse2_id, ranking=10)
    distance_core.add_distance(rse3_id, rse4_id, ranking=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'globus_endpoint_id', rse_id)

    # Single submission
    did1 = did_factory.upload_test_file(rse1)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    did2 = did_factory.upload_test_file(rse3)
    rule_core.add_rule(dids=[did2], account=root_account, copies=1, rse_expression=rse4, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    with patch('rucio.transfertool.globus.bulk_submit_xfer') as mock_bulk_submit:
        mock_bulk_submit.return_value = 0
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertool='globus', transfertype='single', filter_transfertool=None)
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
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertool='globus', transfertype='bulk', filter_transfertool=None)

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
    request = request_core.get_request_by_did(rse_id=rse4_id, **did2)
    assert request['state'] == RequestState.SUBMITTED
