# -*- coding: utf-8 -*-
# Copyright 2015-2022 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2015-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016
# - Martin Barisits <martin.barisits@cern.ch>, 2019-2022
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022
# - Mayank Sharma <imptodefeat@gmail.com>, 2021-2022
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Joel Dierkes <joel.dierkes@cern.ch>, 2021

import threading
import time
from datetime import datetime, timedelta
from unittest.mock import patch
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import pytest

import rucio.daemons.reaper.reaper
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid
from rucio.common.exception import ReplicaNotFound, RequestNotFound
from rucio.core import config as core_config
from rucio.core import distance as distance_core
from rucio.core import replica as replica_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.daemons.conveyor.finisher import finisher
from rucio.daemons.conveyor.poller import poller
from rucio.daemons.conveyor.preparer import preparer
from rucio.daemons.conveyor.submitter import submitter
from rucio.daemons.conveyor.stager import stager
from rucio.daemons.conveyor.throttler import throttler
from rucio.daemons.conveyor.receiver import receiver, graceful_stop as receiver_graceful_stop
from rucio.daemons.reaper.reaper import reaper
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, RequestType, ReplicaState, RSEType
from rucio.db.sqla.session import read_session, transactional_session
from rucio.tests.common import skip_rse_tests_with_accounts
from rucio.transfertool.fts3 import FTS3Transfertool

MAX_POLL_WAIT_SECONDS = 60
TEST_FTS_HOST = 'https://fts:8446'


def __wait_for_replica_transfer(dst_rse_id, scope, name, state=ReplicaState.AVAILABLE, max_wait_seconds=MAX_POLL_WAIT_SECONDS):
    """
    Wait for the replica to become AVAILABLE on the given RSE as a result of a pending transfer
    """
    replica = None
    for _ in range(max_wait_seconds):
        poller(once=True, older_than=0, partition_wait_time=None)
        finisher(once=True, partition_wait_time=None)
        replica = replica_core.get_replica(rse_id=dst_rse_id, scope=scope, name=name)
        if replica['state'] == state:
            break
        time.sleep(1)
    return replica


def __wait_for_request_state(dst_rse_id, scope, name, state, max_wait_seconds=MAX_POLL_WAIT_SECONDS, run_poller=True, run_finisher=False):
    """
    Wait for the request state to be updated to the given expected state as a result of a pending transfer
    """
    request = None
    for _ in range(max_wait_seconds):
        if run_poller:
            poller(once=True, older_than=0, partition_wait_time=None)
        if run_finisher:
            finisher(once=True, partition_wait_time=None)
        request = request_core.get_request_by_did(rse_id=dst_rse_id, scope=scope, name=name)
        if request['state'] == state:
            break
        time.sleep(1)
    return request


def __wait_for_fts_state(request, expected_state, max_wait_seconds=MAX_POLL_WAIT_SECONDS):
    job_state = ''
    for _ in range(max_wait_seconds):
        fts_response = FTS3Transfertool(external_host=TEST_FTS_HOST).bulk_query(request['external_id'])
        job_state = fts_response[request['external_id']][request['id']]['job_state']
        if job_state == expected_state:
            break
        time.sleep(1)
    return job_state


def set_query_parameters(url, params):
    """
    Set a query parameter in an url which may, or may not, have other existing query parameters
    """
    url_parts = list(urlparse(url))

    query = dict(parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urlencode(query)

    return urlunparse(url_parts)


@read_session
def __get_source(request_id, src_rse_id, scope, name, session=None):
    return session.query(models.Source) \
        .filter(models.Source.request_id == request_id) \
        .filter(models.Source.scope == scope) \
        .filter(models.Source.name == name) \
        .filter(models.Source.rse_id == src_rse_id) \
        .first()


@pytest.mark.skip(reason="Needs to be improved as discussed in #5190")
@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher; changes XRD3 usage and limits")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
    ('transfers', 'multihop_tombstone_delay', -1),  # Set OBSOLETE tombstone for intermediate replicas
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
    'rucio.daemons.reaper.reaper.REGION',
]}], indirect=True)
@pytest.mark.parametrize("file_config_mock", [
    # Run test twice: with, and without, temp tables
    {
        "overrides": [
            ('core', 'use_temp_tables', 'True'),
        ]
    },
    {
        "overrides": [
            ('core', 'use_temp_tables', 'False'),
        ]
    }
], indirect=True)
def test_multihop_intermediate_replica_lifecycle(vo, did_factory, root_account, core_config_mock, caches_mock, metrics_mock, file_config_mock):
    """
    Ensure that intermediate replicas created by the submitter are protected from deletion even if their tombstone is
    set to epoch.
    After successful transfers, intermediate replicas with default (epoch) tombstone must be removed. The others must
    be left intact.
    """
    src_rse1_name = 'XRD1'
    src_rse1_id = rse_core.get_rse_id(rse=src_rse1_name, vo=vo)
    src_rse2_name = 'XRD2'
    src_rse2_id = rse_core.get_rse_id(rse=src_rse2_name, vo=vo)
    jump_rse_name = 'XRD3'
    jump_rse_id = rse_core.get_rse_id(rse=jump_rse_name, vo=vo)
    dst_rse_name = 'XRD4'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse_name, vo=vo)

    all_rses = [src_rse1_id, src_rse2_id, jump_rse_id, dst_rse_id]
    did = did_factory.upload_test_file(src_rse1_name)

    # Copy replica to a second source. To avoid the special case of having a unique last replica, which could be handled in a special (more careful) way
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=src_rse2_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=src_rse2_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE

    rse_core.set_rse_limits(rse_id=jump_rse_id, name='MinFreeSpace', value=1)
    rse_core.set_rse_usage(rse_id=jump_rse_id, source='storage', used=1, free=0)
    try:
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Submit transfers to FTS
        # Ensure a replica was created on the intermediary host with epoch tombstone
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertype='single', filter_transfertool=None)
        request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
        assert request['state'] == RequestState.SUBMITTED
        replica = replica_core.get_replica(rse_id=jump_rse_id, **did)
        assert replica['tombstone'] == datetime(year=1970, month=1, day=1)
        assert replica['state'] == ReplicaState.COPYING

        # The intermediate replica is protected by its state (Copying)
        rucio.daemons.reaper.reaper.REGION.invalidate()
        reaper(once=True, rses=[], include_rses=jump_rse_name, exclude_rses=None)
        replica = replica_core.get_replica(rse_id=jump_rse_id, **did)
        assert replica['state'] == ReplicaState.COPYING

        # Wait for the intermediate replica to become ready
        replica = __wait_for_replica_transfer(dst_rse_id=jump_rse_id, **did)
        assert replica['state'] == ReplicaState.AVAILABLE

        # FTS can fail the second transfer
        # run submitter again to copy from jump rse to destination rse
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertype='single', filter_transfertool=None)

        # Wait for the destination replica to become ready
        replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did, max_wait_seconds=120)
        assert replica['state'] == ReplicaState.AVAILABLE

        rucio.daemons.reaper.reaper.REGION.invalidate()
        reaper(once=True, rses=[], include_rses='test_container_xrd=True', exclude_rses=None)

        with pytest.raises(ReplicaNotFound):
            replica_core.get_replica(rse_id=jump_rse_id, **did)

        # 4 request: copy to second source + 1 multihop with two hops (but second hop fails) + re-scheduled second hop
        # Use inequalities, because there can be left-overs from other tests
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 4
        assert metrics_mock.get_sample_value('rucio_core_request_submit_transfer_total') >= 4
        # at least the failed hop
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_finisher_handle_requests_total') > 0
    finally:

        @transactional_session
        def _cleanup_all_usage_and_limits(rse_id, session=None):
            session.query(models.RSELimit).filter_by(rse_id=rse_id).delete()
            session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='storage').delete()

        _cleanup_all_usage_and_limits(rse_id=jump_rse_id)


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_fts_non_recoverable_failures_handled_on_multihop(vo, did_factory, root_account, replica_client, core_config_mock, caches_mock, metrics_mock):
    """
    Verify that the poller correctly handles non-recoverable FTS job failures
    """
    src_rse = 'XRD1'
    src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
    jump_rse = 'XRD3'
    jump_rse_id = rse_core.get_rse_id(rse=jump_rse, vo=vo)
    dst_rse = 'XRD4'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)

    all_rses = [src_rse_id, jump_rse_id, dst_rse_id]

    # Register a did which doesn't exist. It will trigger an non-recoverable error during the FTS transfer.
    did = did_factory.random_did()
    replica_client.add_replicas(rse=src_rse, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.FAILED, **did)
    assert 'Unused hop in multi-hop' in request['err_msg']
    assert request['state'] == RequestState.FAILED
    request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    assert request['state'] == RequestState.FAILED
    assert request['attributes']['source_replica_expression'] == src_rse

    # Each hop is a separate transfer, which will be handled by the poller and marked as failed
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 2

    finisher(once=True, partition_wait_time=None)
    # The intermediate request must not be re-scheduled by finisher
    with pytest.raises(RequestNotFound):
        request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    # ensure tha the ranking was correctly decreased for the whole path
    assert __get_source(request_id=request['id'], src_rse_id=jump_rse_id, **did).ranking == -1
    assert __get_source(request_id=request['id'], src_rse_id=src_rse_id, **did).ranking == -1
    assert request['state'] == RequestState.QUEUED


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_fts_recoverable_failures_handled_on_multihop(vo, did_factory, root_account, replica_client, file_factory, core_config_mock, caches_mock, metrics_mock):
    """
    Verify that the poller correctly handles recoverable FTS job failures
    """
    src_rse = 'XRD1'
    src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
    jump_rse = 'XRD3'
    jump_rse_id = rse_core.get_rse_id(rse=jump_rse, vo=vo)
    dst_rse = 'XRD4'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)

    all_rses = [src_rse_id, jump_rse_id, dst_rse_id]

    # Create and upload a real file, but register it with wrong checksum. This will trigger
    # a FTS "Recoverable" failure on checksum validation
    local_file = file_factory.file_generator()
    did = did_factory.random_did()
    did_factory.upload_client.upload(
        [
            {
                'path': local_file,
                'rse': src_rse,
                'did_scope': did['scope'].external,
                'did_name': did['name'],
                'no_register': True,
            }
        ]
    )
    replica_client.add_replicas(rse=src_rse, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.FAILED, **did)
    assert request['state'] == RequestState.FAILED
    request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    assert request['state'] == RequestState.FAILED

    # Each hop is a separate transfer, which will be handled by the poller and marked as failed
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 2


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_multisource(vo, did_factory, root_account, replica_client, core_config_mock, caches_mock, metrics_mock):
    src_rse1 = 'XRD4'
    src_rse1_id = rse_core.get_rse_id(rse=src_rse1, vo=vo)
    src_rse2 = 'XRD1'
    src_rse2_id = rse_core.get_rse_id(rse=src_rse2, vo=vo)
    dst_rse = 'XRD3'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)

    all_rses = [src_rse1_id, src_rse2_id, dst_rse_id]

    # Add a good replica on the RSE which has a higher distance ranking
    did = did_factory.upload_test_file(src_rse1)
    # Add non-existing replica which will fail during multisource transfers on the RSE with lower cost (will be the preferred source)
    replica_client.add_replicas(rse=src_rse2, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    @read_session
    def __source_exists(src_rse_id, scope, name, session=None):
        return session.query(models.Source) \
            .filter(models.Source.rse_id == src_rse_id) \
            .filter(models.Source.scope == scope) \
            .filter(models.Source.name == name) \
            .count() != 0

    # Entries in the source table must be created for both sources of the multi-source transfer
    assert __source_exists(src_rse_id=src_rse1_id, **did)
    assert __source_exists(src_rse_id=src_rse2_id, **did)

    # After submission, the source rse is the one which will fail
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['source_rse'] == src_rse2
    assert request['source_rse_id'] == src_rse2_id

    # The source_rse must be updated to the correct one
    request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.DONE, **did)
    assert request['source_rse'] == src_rse1
    assert request['source_rse_id'] == src_rse1_id

    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE

    # Both entries in source table must be removed after completion
    assert not __source_exists(src_rse_id=src_rse1_id, **did)
    assert not __source_exists(src_rse_id=src_rse2_id, **did)

    # Only one request was handled; doesn't matter that it's multisource
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_finisher_handle_requests_total') >= 1
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 1
    assert metrics_mock.get_sample_value(
        'rucio_core_request_get_next_total',
        labels={
            'request_type': 'TRANSFER.STAGEIN.STAGEOUT',
            'state': 'DONE.FAILED.LOST.SUBMITTING.SUBMISSION_FAILED.NO_SOURCES.ONLY_TAPE_SOURCES.MISMATCH_SCHEME'}
    )


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter and receiver")
def test_multisource_receiver(vo, did_factory, replica_client, root_account, metrics_mock):
    """
    Run receiver as a background thread to automatically handle fts notifications.
    Ensure that a multi-source job in which the first source fails is correctly handled by receiver.
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'full_mode': True, 'all_vos': True, 'total_threads': 1})
    receiver_thread.start()

    try:
        src_rse1 = 'XRD4'
        src_rse1_id = rse_core.get_rse_id(rse=src_rse1, vo=vo)
        src_rse2 = 'XRD1'
        src_rse2_id = rse_core.get_rse_id(rse=src_rse2, vo=vo)
        dst_rse = 'XRD3'
        dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)

        all_rses = [src_rse1_id, src_rse2_id, dst_rse_id]

        # Add a good replica on the RSE which has a higher distance ranking
        did = did_factory.upload_test_file(src_rse1)
        # Add non-existing replica which will fail during multisource transfers on the RSE with lower cost (will be the preferred source)
        replica_client.add_replicas(rse=src_rse2, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

        # After submission, the source rse is the one which will fail
        request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
        assert request['source_rse'] == src_rse2
        assert request['source_rse_id'] == src_rse2_id

        request = None
        for _ in range(MAX_POLL_WAIT_SECONDS):
            request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
            # The request must not be marked as failed. Not even temporarily. It is a multi-source transfer and the
            # the first, failed, source must not change the replica state. We must wait for all sources to be tried.
            assert request['state'] != RequestState.FAILED
            if request['state'] == RequestState.DONE:
                break
            time.sleep(1)
        assert request['state'] == RequestState.DONE

        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_receiver_update_request_state_total', labels={'updated': 'True'}) >= 1
        # The source was updated to the good one
        assert request['source_rse'] == src_rse1
        assert request['source_rse_id'] == src_rse1_id
    finally:
        receiver_graceful_stop.set()
        receiver_thread.join(timeout=5)
        receiver_graceful_stop.clear()


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter and receiver")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_multihop_receiver_on_failure(vo, did_factory, replica_client, root_account, core_config_mock, caches_mock, metrics_mock):
    """
    Verify that the receiver correctly handles multihop jobs which fail
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'full_mode': True, 'all_vos': True, 'total_threads': 1})
    receiver_thread.start()

    try:
        src_rse = 'XRD1'
        src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
        jump_rse = 'XRD3'
        jump_rse_id = rse_core.get_rse_id(rse=jump_rse, vo=vo)
        dst_rse = 'XRD4'
        dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)

        all_rses = [src_rse_id, jump_rse_id, dst_rse_id]

        # Register a did which doesn't exist. It will trigger a failure error during the FTS transfer.
        did = did_factory.random_did()
        replica_client.add_replicas(rse=src_rse, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

        request = __wait_for_request_state(dst_rse_id=jump_rse_id, state=RequestState.FAILED, run_poller=False, **did)
        assert request['state'] == RequestState.FAILED
        # We use FTS "Completion" messages in receiver. In case of multi-hops transfer failures, FTS doesn't start
        # next transfers; so it never sends a "completion" message for some hops. Rely on poller in such cases.
        # TODO: set the run_poller argument to False if we ever manage to make the receiver correctly handle multi-hop failures.
        request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.FAILED, run_poller=True, **did)
        assert request['state'] == RequestState.FAILED
        assert 'Unused hop in multi-hop' in request['err_msg']

        # First hop will be handled by receiver; second hop by poller
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_receiver_update_request_state_total', labels={'updated': 'True'}) >= 1
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 1

        finisher(once=True, partition_wait_time=None)
        # The intermediate request must not be re-scheduled by finisher
        with pytest.raises(RequestNotFound):
            request_core.get_request_by_did(rse_id=jump_rse_id, **did)
        request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
        # ensure tha the ranking was correctly decreased for the whole path
        assert __get_source(request_id=request['id'], src_rse_id=jump_rse_id, **did).ranking == -1
        assert __get_source(request_id=request['id'], src_rse_id=src_rse_id, **did).ranking == -1
        assert request['state'] == RequestState.QUEUED
    finally:
        receiver_graceful_stop.set()
        receiver_thread.join(timeout=5)
        receiver_graceful_stop.clear()


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter and receiver")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
]}], indirect=True)
def test_multihop_receiver_on_success(vo, did_factory, root_account, core_config_mock, caches_mock, metrics_mock):
    """
    Verify that the receiver correctly handles successful multihop jobs
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'full_mode': True, 'all_vos': True, 'total_threads': 1})
    receiver_thread.start()

    try:
        src_rse = 'XRD1'
        src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
        jump_rse = 'XRD3'
        jump_rse_id = rse_core.get_rse_id(rse=jump_rse, vo=vo)
        dst_rse = 'XRD4'
        dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)

        all_rses = [src_rse_id, jump_rse_id, dst_rse_id]

        did = did_factory.upload_test_file(src_rse)
        rule_priority = 5
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None, priority=rule_priority)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

        request = __wait_for_request_state(dst_rse_id=jump_rse_id, state=RequestState.DONE, run_poller=False, **did)
        assert request['state'] == RequestState.DONE
        request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.DONE, run_poller=False, **did)
        assert request['state'] == RequestState.DONE

        fts_response = FTS3Transfertool(external_host=TEST_FTS_HOST).bulk_query(request['external_id'])
        assert fts_response[request['external_id']][request['id']]['priority'] == rule_priority

        # Two hops; both handled by receiver
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_receiver_update_request_state_total', labels={'updated': 'True'}) >= 2
    finally:
        receiver_graceful_stop.set()
        receiver_thread.join(timeout=5)
        receiver_graceful_stop.clear()


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="runs multiple conveyor daemons")
@pytest.mark.parametrize("file_config_mock", [{
    "overrides": [('conveyor', 'use_preparer', 'true')]
}], indirect=True)
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'DEST_PER_ALL_ACT')]
}], indirect=True)
def test_preparer_throttler_submitter(rse_factory, did_factory, root_account, file_config_mock, core_config_mock, metrics_mock):
    """
    Integration test of the preparer/throttler workflow.
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse1, dst_rse_id1 = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse2, dst_rse_id2 = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id1, dst_rse_id2]

    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)
    distance_core.add_distance(src_rse_id, dst_rse_id1, ranking=10)
    distance_core.add_distance(src_rse_id, dst_rse_id2, ranking=10)
    # Set limits only for one of the RSEs
    rse_core.set_rse_transfer_limits(dst_rse_id1, max_transfers=1, activity='all_activities', strategy='fifo')

    did1 = did_factory.upload_test_file(src_rse)
    did2 = did_factory.upload_test_file(src_rse)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=dst_rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    rule_core.add_rule(dids=[did2], account=root_account, copies=1, rse_expression=dst_rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=dst_rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did1)
    assert request['state'] == RequestState.PREPARING
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did2)
    assert request['state'] == RequestState.PREPARING
    request = request_core.get_request_by_did(rse_id=dst_rse_id2, **did1)
    assert request['state'] == RequestState.PREPARING

    # submitter must not work on PREPARING replicas
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    # One RSE has limits set: the requests will be moved to WAITING status; the other RSE has no limits: go directly to queued
    preparer(once=True, sleep_time=1, bulk=100, partition_wait_time=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did1)
    assert request['state'] == RequestState.WAITING
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did2)
    assert request['state'] == RequestState.WAITING
    request = request_core.get_request_by_did(rse_id=dst_rse_id2, **did1)
    assert request['state'] == RequestState.QUEUED

    # submitter must not work on WAITING replicas
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    # One of the waiting requests will be queued, the second will remain in waiting state
    throttler(once=True, partition_wait_time=None)
    # Check metrics.
    # This gauge values are recorded at the beginning of the execution. Hence 2 waiting and 0 transfers
    gauge_name = 'rucio_daemons_conveyor_throttler_set_rse_transfer_limits'
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'max_transfers'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'transfers'}) == 0
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'waiting'}) == 2
    request1 = request_core.get_request_by_did(rse_id=dst_rse_id1, **did1)
    request2 = request_core.get_request_by_did(rse_id=dst_rse_id1, **did2)
    # one request WAITING and other QUEUED
    assert (request1['state'] == RequestState.WAITING and request2['state'] == RequestState.QUEUED
            or request1['state'] == RequestState.QUEUED and request2['state'] == RequestState.WAITING)
    waiting_did = did1 if request1['state'] == RequestState.WAITING else did2
    queued_did = did1 if request1['state'] == RequestState.QUEUED else did2

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    # Calling the throttler again will not schedule the waiting request, because there is a submitted one
    throttler(once=True, partition_wait_time=None)
    # This gauge values are recorded at the beginning of the execution. Hence 1 waiting and one transfer
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'max_transfers'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'transfers'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'waiting'}) == 1
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **waiting_did)
    assert request['state'] == RequestState.WAITING

    request = __wait_for_request_state(dst_rse_id=dst_rse_id1, state=RequestState.DONE, **queued_did)
    assert request['state'] == RequestState.DONE
    request = __wait_for_request_state(dst_rse_id=dst_rse_id2, state=RequestState.DONE, **did1)
    assert request['state'] == RequestState.DONE

    # Now that the submitted transfers are finished, the WAITING one can be queued
    throttler(once=True, partition_wait_time=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **waiting_did)
    assert request['state'] == RequestState.QUEUED


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.common.rse_attributes.REGION',
    'rucio.core.rse.REGION',
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_non_deterministic_dst(did_factory, did_client, root_account, vo, caches_mock):
    """
    Test a transfer towards a non-deterministic RSE
    """
    src_rse = 'XRD3'
    src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
    dst_rse = 'XRD4'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)
    all_rses = [src_rse_id, dst_rse_id]

    did = did_factory.upload_test_file(src_rse)
    # Dataset name is part of the non-deterministic path
    dataset = did_factory.make_dataset()
    did_client.add_files_to_dataset(files=[{'scope': did['scope'].external, 'name': did['name']}], scope=dataset['scope'].external, name=dataset['name'])

    rse_core.update_rse(rse_id=dst_rse_id, parameters={'deterministic': False})
    try:
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

        replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
        assert replica['state'] == ReplicaState.AVAILABLE
    finally:
        rse_core.update_rse(rse_id=dst_rse_id, parameters={'deterministic': True})


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="runs stager; poller and finisher")
def test_stager(rse_factory, did_factory, root_account, replica_client):
    """
    Submit a real transfer to FTS and rely on the gfal "mock" plugin to report a simulated "success"
    https://gitlab.cern.ch/dmc/gfal2/-/blob/master/src/plugins/mock/README_PLUGIN_MOCK
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id]

    distance_core.add_distance(src_rse_id, dst_rse_id, ranking=10)
    rse_core.add_rse_attribute(src_rse_id, 'staging_buffer', dst_rse)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

    did = did_factory.upload_test_file(src_rse)
    replica = replica_core.get_replica(rse_id=src_rse_id, **did)

    replica_client.add_replicas(rse=dst_rse, files=[{'scope': did['scope'].external, 'name': did['name'], 'state': 'C',
                                                     'bytes': replica['bytes'], 'adler32': replica['adler32'], 'md5': replica['md5']}])
    request_core.queue_requests(requests=[{'dest_rse_id': dst_rse_id,
                                           'scope': did['scope'],
                                           'name': did['name'],
                                           'rule_id': '00000000000000000000000000000000',
                                           'attributes': {
                                               'source_replica_expression': src_rse,
                                               'activity': 'Some Activity',
                                               'bytes': replica['bytes'],
                                               'adler32': replica['adler32'],
                                               'md5': replica['md5'],
                                           },
                                           'request_type': RequestType.STAGEIN,
                                           'retry_count': 0,
                                           'account': root_account,
                                           'requested_at': datetime.now()}])
    stager(once=True, rses=[{'id': rse_id} for rse_id in all_rses])

    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, max_wait_seconds=2 * MAX_POLL_WAIT_SECONDS, **did)
    assert replica['state'] == ReplicaState.AVAILABLE


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
def test_lost_transfers(rse_factory, did_factory, root_account):
    """
    Correctly handle FTS "404 not found" errors.
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id]

    distance_core.add_distance(src_rse_id, dst_rse_id, ranking=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

    did = did_factory.upload_test_file(src_rse)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    @transactional_session
    def __update_request(request_id, session=None, **kwargs):
        session.query(models.Request).filter_by(id=request_id).update(kwargs, synchronize_session=False)

    # Fake that the transfer is submitted and lost
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    __update_request(request['id'], external_id='some-fake-random-id')

    # The request must be marked lost
    request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.LOST, **did)
    assert request['state'] == RequestState.LOST

    # Set update time far in the past to bypass protections (not resubmitting too fast).
    # Run finisher and submitter, the request must be resubmitted and transferred correctly
    __update_request(request['id'], updated_at=datetime.utcnow() - timedelta(days=1))
    finisher(once=True, partition_wait_time=None)
    # The source ranking must not be updated for submission failures and lost transfers
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert __get_source(request_id=request['id'], src_rse_id=src_rse_id, **did).ranking == 0
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
def test_cancel_rule(rse_factory, did_factory, root_account):
    """
    Ensure that, when we cancel a rule, the request is cancelled in FTS
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id]

    distance_core.add_distance(src_rse_id, dst_rse_id, ranking=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

    did = did_factory.upload_test_file(src_rse)

    [rule_id] = rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    class _FTSWrapper(FTSWrapper):
        @staticmethod
        def on_submit(file):
            # Simulate using the mock gfal plugin that it takes a long time to copy the file
            file['sources'] = [set_query_parameters(s_url, {'time': 30}) for s_url in file['sources']]

    with patch('rucio.daemons.conveyor.submitter.TRANSFERTOOL_CLASSES_BY_NAME') as tt_mock:
        tt_mock.__getitem__.return_value = _FTSWrapper
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    rule_core.delete_rule(rule_id)

    with pytest.raises(RequestNotFound):
        request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    fts_response = FTS3Transfertool(external_host=TEST_FTS_HOST).bulk_query(request['external_id'])
    assert fts_response[request['external_id']][request['id']]['job_state'] == 'CANCELED'


class FTSWrapper(FTS3Transfertool):
    """
    Used to alter the JSON exchange with FTS.

    One use-case would be to use the "mock" gfal plugin (by using a mock:// protocol/scheme) to simulate failuare on fts side.
    For example, adding size_pre=<something> url parameter would result in "stat" calls on FTS side to return(simulate) this file size.
    https://gitlab.cern.ch/dmc/gfal2/-/blob/master/src/plugins/mock/README_PLUGIN_MOCK
    """

    @staticmethod
    def on_submit(file):
        pass

    @staticmethod
    def on_receive(job_response):
        pass

    @classmethod
    def _FTS3Transfertool__file_from_transfer(cls, transfer, job_params):
        file = super()._FTS3Transfertool__file_from_transfer(transfer, job_params)
        cls.on_submit(file)
        return file

    def _FTS3Transfertool__bulk_query_responses(self, jobs_response):
        self.on_receive(jobs_response)
        return super()._FTS3Transfertool__bulk_query_responses(jobs_response)


@pytest.fixture
def overwrite_on_tape_topology(rse_factory, did_factory, root_account, vo, file_factory):
    """
    Prepares the XRD* RSEs for an overwrite_on_tape test.
    - fakes that one xroot RSE is a tape destination (and rollbacks the change after the test)

    Return a factory which allows to upload/register/add_rule for two dids
    """

    rse1 = 'XRD1'
    rse1_id = rse_core.get_rse_id(rse=rse1, vo=vo)
    rse2 = 'XRD3'
    rse2_id = rse_core.get_rse_id(rse=rse2, vo=vo)
    rse3 = 'XRD4'
    rse3_id = rse_core.get_rse_id(rse=rse3, vo=vo)

    def __generate_and_upload_file(src_rse, dst_rse, simulate_dst_corrupted=False):
        """
        Create and upload real files to source and destination. Don't register it on destination. This way, fts will fail if overwrite = False

        If simulate_dst_corrupted is True, will upload a different file to destination, to simulate that it is corrupted
        """
        local_file = file_factory.file_generator()
        did = did_factory.random_did()
        did_factory.upload_test_file(src_rse, path=local_file, **did)
        did_factory.upload_client.upload(
            [
                {
                    'path': file_factory.file_generator(size=3) if simulate_dst_corrupted else local_file,
                    'rse': dst_rse,
                    'did_scope': did['scope'].external,
                    'did_name': did['name'],
                    'no_register': True,
                }
            ]
        )
        return did

    def __create_dids(did1_corrupted=True, did2_corrupted=True):
        """
        Uploads two files:
        - one which requires multiple transfer hop to go to destination
        - one which can be transferred in one hop to destination rse
        """
        # multihop transfer:
        did1 = __generate_and_upload_file(rse1, rse3, simulate_dst_corrupted=did1_corrupted)
        # direct transfer
        did2 = __generate_and_upload_file(rse2, rse3, simulate_dst_corrupted=did2_corrupted)
        rule_core.add_rule(dids=[did1, did2], account=root_account, copies=1, rse_expression=rse3, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        return rse1_id, rse2_id, rse3_id, did1, did2

    # Fake that destination RSE is a tape
    rse_core.update_rse(rse_id=rse3_id, parameters={'rse_type': RSEType.TAPE})
    try:
        rse_core.add_rse_attribute(rse3_id, 'archive_timeout', 60)
        yield __create_dids
    finally:
        rse_core.update_rse(rse_id=rse3_id, parameters={'rse_type': RSEType.DISK})
        rse_core.del_rse_attribute(rse3_id, 'archive_timeout')


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.common.rse_attributes.REGION',
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_overwrite_on_tape(overwrite_on_tape_topology, core_config_mock, caches_mock):
    """
    Ensure that overwrite is not set for transfers towards TAPE RSEs
    """
    rse1_id, rse2_id, rse3_id, did1, did2 = overwrite_on_tape_topology(did1_corrupted=False, did2_corrupted=True)
    all_rses = [rse1_id, rse2_id, rse3_id]

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did1)
    assert request['state'] == RequestState.FAILED
    assert 'Destination file exists and overwrite is not enabled' in request['err_msg']
    request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did2)
    assert request['state'] == RequestState.FAILED
    assert 'Destination file exists and overwrite is not enabled' in request['err_msg']


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.common.rse_attributes.REGION',
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_file_exists_handled(overwrite_on_tape_topology, core_config_mock, caches_mock):
    """
    If a transfer fails because the destination job_params exists, and the size+checksums of that existing job_params
    are correct, the transfer must be marked successful.
    """
    rse1_id, rse2_id, rse3_id, did1, did2 = overwrite_on_tape_topology(did1_corrupted=False, did2_corrupted=False)
    all_rses = [rse1_id, rse2_id, rse3_id]

    class _FTSWrapper(FTSWrapper):
        @staticmethod
        def on_receive(job_params):
            for job in (job_params if isinstance(job_params, list) else [job_params]):
                for file in job.get('files', []):
                    if (file.get('file_metadata', {}).get('dst_type') == 'TAPE'
                            and file.get('file_metadata', {}).get('dst_file', {}).get('file_on_tape') is not None):
                        # Fake that dst_file metadata contains file_on_tape == True
                        # As we don't really have tape RSEs in our tests, file_on_tape is always false
                        file['file_metadata']['dst_file']['file_on_tape'] = True
            return job_params

    with patch('rucio.core.transfer.FTS3Transfertool', _FTSWrapper):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertype='single', filter_transfertool=None)

        request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.DONE, **did1)
        assert request['state'] == RequestState.DONE
        request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.DONE, **did2)
        assert request['state'] == RequestState.DONE


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers; leaves pending fts transfers in archiving state")
@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
    ('transfers', 'overwrite_corrupted_files', False)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.common.rse_attributes.REGION',
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_overwrite_corrupted_files(overwrite_on_tape_topology, core_config_mock, caches_mock):
    """
    If a transfer fails because the destination exists, and the size+checksums of the destination file are wrong,
    the next submission must be performed according to the overwrite_corrupted_files config paramenter.
    """
    rse1_id, rse2_id, rse3_id, did1, did2 = overwrite_on_tape_topology(did1_corrupted=True, did2_corrupted=True)
    all_rses = [rse1_id, rse2_id, rse3_id]

    class _FTSWrapper(FTSWrapper):
        @staticmethod
        def on_receive(job_params):
            for job in (job_params if isinstance(job_params, list) else [job_params]):
                for file in job.get('files', []):
                    if (file.get('file_metadata', {}).get('dst_type') == 'TAPE'
                            and file.get('file_metadata', {}).get('dst_file', {}).get('file_on_tape') is not None):
                        # Fake that dst_file metadata contains file_on_tape == True
                        # As we don't really have tape RSEs in our tests, file_on_tape is always false
                        file['file_metadata']['dst_file']['file_on_tape'] = True
            return job_params

    with patch('rucio.core.transfer.FTS3Transfertool', _FTSWrapper):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertype='single', filter_transfertool=None)
        # Both transfers must be marked as failed because the file size is incorrect
        request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did1)
        assert request['state'] == RequestState.FAILED
        request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did2)
        assert request['state'] == RequestState.FAILED

        # Re-submit the failed requests. They must fail again, because overwrite_corrupted_files is False
        finisher(once=True, partition_wait_time=None)
        request = request_core.get_request_by_did(rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.QUEUED
        request = request_core.get_request_by_did(rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.QUEUED
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertype='single', filter_transfertool=None)
        # Set overwrite to True before running the poller or finisher
        core_config.set('transfers', 'overwrite_corrupted_files', True)
        request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did1)
        assert request['state'] == RequestState.FAILED
        request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did2)
        assert request['state'] == RequestState.FAILED

        # Re-submit one more time. Now the destination file must be overwritten
        finisher(once=True, partition_wait_time=None)
        request = request_core.get_request_by_did(rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.QUEUED
        request = request_core.get_request_by_did(rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.QUEUED
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertype='single', filter_transfertool=None)
        request = request_core.get_request_by_did(rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.SUBMITTED
        assert __wait_for_fts_state(request, expected_state='ARCHIVING') == 'ARCHIVING'
        request = request_core.get_request_by_did(rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.SUBMITTED
        assert __wait_for_fts_state(request, expected_state='ARCHIVING') == 'ARCHIVING'


@pytest.mark.noparallel(reason="runs submitter; poller and finisher")
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('conveyor', 'usercert', 'DEFAULT_DUMMY_CERT'),
    ('vo_certs', 'new', 'NEW_VO_DUMMY_CERT'),
]}], indirect=True)
def test_multi_vo_certificates(file_config_mock, rse_factory, did_factory, scope_factory, vo, second_vo):
    """
    Test that submitter and poller call fts with correct certificates in multi-vo env
    """

    _, [scope1, scope2] = scope_factory(vos=[vo, second_vo])

    def __init_test_for_vo(vo, scope):
        src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', vo=vo)
        dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', vo=vo)
        all_rses = [src_rse_id, dst_rse_id]

        for rse_id in all_rses:
            rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)
        distance_core.add_distance(src_rse_id, dst_rse_id, ranking=10)
        account = InternalAccount('root', vo=vo)
        did = did_factory.random_did(scope=scope)
        replica_core.add_replica(rse_id=src_rse_id, scope=scope, name=did['name'], bytes_=1, account=account, adler32=None, md5=None)
        rule_core.add_rule(dids=[did], account=account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None,
                           lifetime=None, locked=False, subscription_id=None, ignore_account_limit=True)
        return all_rses

    all_rses = []
    rses = __init_test_for_vo(vo=vo, scope=scope1)
    all_rses.extend(rses)
    rses = __init_test_for_vo(vo=second_vo, scope=scope2)
    all_rses.extend(rses)

    certs_used_by_submitter = []
    certs_used_by_poller = []

    class _FTSWrapper(FTS3Transfertool):
        # Override fts3 transfertool. Don't actually perform any interaction with fts; and record the certificates used
        def submit(self, transfers, job_params, timeout=None):
            certs_used_by_submitter.append(self.cert[0])
            return generate_uuid()

        def bulk_query(self, transfer_ids, timeout=None):
            certs_used_by_poller.append(self.cert[0])
            return {}

    with patch('rucio.daemons.conveyor.submitter.TRANSFERTOOL_CLASSES_BY_NAME') as tt_mock:
        tt_mock.__getitem__.return_value = _FTSWrapper
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)
        assert sorted(certs_used_by_submitter) == ['DEFAULT_DUMMY_CERT', 'NEW_VO_DUMMY_CERT']

    with patch('rucio.core.transfer.FTS3Transfertool', _FTSWrapper):
        poller(once=True, older_than=0, partition_wait_time=None)
        assert sorted(certs_used_by_poller) == ['DEFAULT_DUMMY_CERT', 'NEW_VO_DUMMY_CERT']
