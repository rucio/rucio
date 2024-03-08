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
import logging
import threading
import time
from datetime import datetime, timedelta
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
from sqlalchemy import update

import pytest

import rucio.daemons.reaper.reaper
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid, adler32
from rucio.common.exception import ReplicaNotFound, RequestNotFound
from rucio.core import config as core_config
from rucio.core import did as did_core
from rucio.core import distance as distance_core
from rucio.core import lock as lock_core
from rucio.core import message as message_core
from rucio.core import replica as replica_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.core.account_limit import set_local_account_limit
from rucio.daemons.conveyor.finisher import finisher
from rucio.daemons.conveyor.poller import poller
from rucio.daemons.conveyor.preparer import preparer
from rucio.daemons.conveyor.submitter import submitter
from rucio.daemons.conveyor.stager import stager
from rucio.daemons.conveyor.throttler import throttler
from rucio.daemons.conveyor.receiver import receiver, GRACEFUL_STOP as receiver_graceful_stop, Receiver
from rucio.daemons.reaper.reaper import reaper
from rucio.db.sqla import models
from rucio.db.sqla.constants import LockState, RequestState, RequestType, ReplicaState, RSEType, RuleState
from rucio.db.sqla.session import read_session, transactional_session
from rucio.tests.common import skip_rse_tests_with_accounts
from rucio.transfertool.fts3 import FTS3Transfertool
from tests.ruciopytest import NoParallelGroups
from tests.mocks.mock_http_server import MockServer

MAX_POLL_WAIT_SECONDS = 100
TEST_FTS_HOST = 'https://fts:8446'


@transactional_session
def __update_request(request_id, *, session=None, **kwargs):
    session.query(models.Request).filter_by(id=request_id).update(kwargs, synchronize_session=False)


def __wait_for_replica_transfer(dst_rse_id, scope, name, max_wait_seconds=MAX_POLL_WAIT_SECONDS, transfertool=None):
    """
    Wait for the replica to become AVAILABLE on the given RSE as a result of a pending transfer
    """
    replica = {}
    for _ in range(max_wait_seconds):
        poller(once=True, older_than=0, partition_wait_time=0, transfertool=transfertool)
        finisher(once=True, partition_wait_time=0)
        replica = replica_core.get_replica(rse_id=dst_rse_id, scope=scope, name=name)
        if replica['state'] != ReplicaState.COPYING:
            break
        time.sleep(1)
    return replica


def __wait_for_state_transition(dst_rse_id, scope, name, max_wait_seconds=MAX_POLL_WAIT_SECONDS, run_poller=True, transfertool=None):
    """
    Wait for the request state to be updated to the given expected state as a result of a pending transfer
    """
    request = {}
    for _ in range(max_wait_seconds):
        if run_poller:
            poller(once=True, older_than=0, partition_wait_time=0, transfertool=transfertool)
        request = request_core.get_request_by_did(rse_id=dst_rse_id, scope=scope, name=name)
        if request['state'] != RequestState.SUBMITTED:
            break
        time.sleep(1)
    return request


def __wait_for_fts_state(request, expected_state, max_wait_seconds=MAX_POLL_WAIT_SECONDS):
    job_state = ''
    for _ in range(max_wait_seconds):
        fts_response = FTS3Transfertool(external_host=TEST_FTS_HOST).bulk_query({request['external_id']: {request['id']: request}})
        job_state = fts_response[request['external_id']][request['id']].job_response['job_state']
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
def __get_source(request_id, src_rse_id, scope, name, *, session=None):
    return session.query(models.Source) \
        .filter(models.Source.request_id == request_id) \
        .filter(models.Source.scope == scope) \
        .filter(models.Source.name == name) \
        .filter(models.Source.rse_id == src_rse_id) \
        .first()


@pytest.fixture
def scitags_mock(core_config_mock):
    """Run a mock http server which always returns the content of scitags.json from test/inputs"""
    from tests.inputs import SCITAGS_JSON
    from pathlib import Path

    class _SendScitagsJson(MockServer.Handler):
        def do_GET(self):
            file_content = Path(SCITAGS_JSON).read_text()
            self.send_code_and_message(200, {'Content-Type': 'application/json'}, file_content)

    with MockServer(_SendScitagsJson) as mock_server:
        core_config.set('packet-marking', 'enabled', True)
        core_config.set('packet-marking', 'fetch_url', mock_server.base_url)
        core_config.set('packet-marking', 'exp_name', 'atlas')
        yield mock_server


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'multihop_tombstone_delay', -1),  # Set OBSOLETE tombstone for intermediate replicas
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
    'rucio.daemons.reaper.reaper.REGION',
]}], indirect=True)
def test_multihop_intermediate_replica_lifecycle(vo, did_factory, root_account, core_config_mock, caches_mock, metrics_mock):
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
    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=src_rse2_name, grouping='ALL', weight=None, lifetime=3600, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=0, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=src_rse2_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE

    rse_core.set_rse_limits(rse_id=jump_rse_id, name='MinFreeSpace', value=1)
    rse_core.set_rse_usage(rse_id=jump_rse_id, source='storage', used=1, free=0)
    try:
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse_name, grouping='ALL', weight=None, lifetime=3600, locked=False, subscription_id=None)

        # Submit transfers to FTS
        # Ensure a replica was created on the intermediary host with epoch tombstone
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=0, transfertype='single', filter_transfertool=None)
        request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
        assert request['state'] == RequestState.SUBMITTED
        replica = replica_core.get_replica(rse_id=jump_rse_id, **did)
        assert replica['tombstone'] == datetime(year=1970, month=1, day=1)
        assert replica['state'] == ReplicaState.COPYING

        request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
        # Fake an existing unused source with raking of 0 for the second source.
        # The ranking of this source should remain at 0 till the end.

        @transactional_session
        def __fake_source_ranking(*, session=None):
            models.Source(request_id=request['id'],
                          scope=request['scope'],
                          name=request['name'],
                          rse_id=src_rse2_id,
                          dest_rse_id=request['dest_rse_id'],
                          ranking=0,
                          bytes=request['bytes'],
                          url=None,
                          is_using=False). \
                save(session=session, flush=False)

        __fake_source_ranking()

        # The intermediate replica is protected by its state (Copying)
        rucio.daemons.reaper.reaper.REGION.invalidate()
        reaper(once=True, rses=[], include_rses=jump_rse_name, exclude_rses=None)
        replica = replica_core.get_replica(rse_id=jump_rse_id, **did)
        assert replica['state'] == ReplicaState.COPYING

        # Wait for the intermediate replica to become ready
        replica = __wait_for_replica_transfer(dst_rse_id=jump_rse_id, **did)
        assert replica['state'] == ReplicaState.AVAILABLE

        # ensure tha the ranking was correct for all sources and intermediate rses
        assert __get_source(request_id=request['id'], src_rse_id=src_rse1_id, **did).ranking == 0
        assert __get_source(request_id=request['id'], src_rse_id=jump_rse_id, **did).ranking == 0
        assert __get_source(request_id=request['id'], src_rse_id=src_rse2_id, **did).ranking == 0
        # Only group_bulk=1 part of the path was submitted.
        # run submitter again to copy from jump rse to destination rse
        __update_request(request_core.get_request_by_did(rse_id=dst_rse_id, **did)['id'], last_processed_by=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=0, transfertype='single', filter_transfertool=None)

        # Wait for the destination replica to become ready
        replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
        assert replica['state'] == ReplicaState.AVAILABLE

        rucio.daemons.reaper.reaper.REGION.invalidate()
        reaper(once=True, rses=[], include_rses='test_container_xrd=True', exclude_rses=None)

        with pytest.raises(ReplicaNotFound):
            replica_core.get_replica(rse_id=jump_rse_id, **did)

        # 3 request: copy to second source + 2 hops (each separately)
        # Use inequalities, because there can be left-overs from other tests
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 3
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_common_submit_transfer_total') >= 3
        # at least the failed hop
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_finisher_handle_requests_total') > 0
    finally:

        @transactional_session
        def _cleanup_all_usage_and_limits(rse_id, *, session=None):
            session.query(models.RSELimit).filter_by(rse_id=rse_id).delete()
            session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='storage').delete()

        _cleanup_all_usage_and_limits(rse_id=jump_rse_id)


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
]}], indirect=True)
def test_fts_non_recoverable_failures_handled_on_multihop(vo, did_factory, root_account, replica_client, caches_mock, metrics_mock):
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
    did = did_factory.random_file_did()
    replica_client.add_replicas(rse=src_rse, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    request = __wait_for_state_transition(dst_rse_id=dst_rse_id, **did)
    assert 'Unused hop in multi-hop' in request['err_msg']
    assert request['state'] == RequestState.FAILED
    request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    assert request['state'] == RequestState.FAILED
    assert request['attributes']['source_replica_expression'] == src_rse

    # Each hop is a separate transfer, which will be handled by the poller and marked as failed
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 2

    # Finisher will handle transfers of the same multihop one hop at a time
    finisher(once=True, partition_wait_time=0)
    finisher(once=True, partition_wait_time=0)
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
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
]}], indirect=True)
def test_fts_recoverable_failures_handled_on_multihop(vo, did_factory, root_account, replica_client, file_factory, caches_mock, metrics_mock):
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
    did = did_factory.random_file_did()
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
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    request = __wait_for_state_transition(dst_rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.FAILED
    request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    assert request['state'] == RequestState.FAILED

    # Each hop is a separate transfer, which will be handled by the poller and marked as failed
    assert metrics_mock.get_sample_value('rucio_daemons_conveyor_poller_update_request_state_total', labels={'updated': 'True'}) >= 2


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
]}], indirect=True)
def test_multisource(vo, did_factory, root_account, replica_client, caches_mock, metrics_mock):
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

    # Submit indirectly, via a container, to test this case
    dataset = did_factory.make_dataset()
    did_core.attach_dids(dids=[did], account=root_account, **dataset)
    container = did_factory.make_container()
    did_core.attach_dids(dids=[dataset], account=root_account, **container)
    rule_core.add_rule(dids=[container], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    @read_session
    def __source_exists(src_rse_id, scope, name, *, session=None):
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
    request = __wait_for_state_transition(dst_rse_id=dst_rse_id, **did)
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
        'rucio_core_request_get_next_requests_total',
        labels={
            'request_type': 'TRANSFER.STAGEIN.STAGEOUT',
            'state': 'DONE.FAILED.LOST.SUBMISSION_FAILED.NO_SOURCES.ONLY_TAPE_SOURCES.MISMATCH_SCHEME'}
    )


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.RECEIVER])
def test_multisource_receiver(vo, did_factory, replica_client, root_account, metrics_mock, message_mock):
    """
    Run receiver as a background thread to automatically handle fts notifications.
    Ensure that a multi-source job in which the first source fails is correctly handled by receiver.
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'all_vos': True, 'total_threads': 1})
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

        # submit using indirectly via a dataset to test this case
        dataset = did_factory.make_dataset()
        did_core.attach_dids(dids=[did], account=root_account, **dataset)
        did_core.set_metadata(did['scope'], did['name'], 'datatype', 'RAW')
        rule_core.add_rule(dids=[dataset], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

        # After submission, the source rse is the one which will fail
        request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
        assert request['source_rse'] == src_rse2
        assert request['source_rse_id'] == src_rse2_id

        request = {}
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

        # Test the content of generated messages
        msgs = message_core.retrieve_messages()
        msg_submitted = next(msg for msg in msgs if msg['event_type'] == 'transfer-submitted')
        assert msg_submitted['payload']['request-id'] == request['id']
        assert msg_submitted['payload']['datatype'] == 'RAW'
        assert msg_submitted['payload']['datasetScope'] == dataset['scope'].external
        assert msg_submitted['payload']['dataset'] == dataset['name']
        msg_done = next(msg for msg in msgs if msg['event_type'] == 'transfer-done')
        assert msg_done['payload']['request-id'] == request['id']
        assert msg_done['payload']['datatype'] == 'RAW'
        assert msg_done['payload']['datasetScope'] == dataset['scope'].external
        assert msg_done['payload']['dataset'] == dataset['name']
        assert msg_done['payload']['transfer_link'].startswith('https://fts:8449/')
    finally:
        receiver_graceful_stop.set()
        receiver_thread.join(timeout=5)
        receiver_graceful_stop.clear()


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.RECEIVER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
]}], indirect=True)
def test_multihop_receiver_on_failure(vo, did_factory, replica_client, root_account, caches_mock, metrics_mock):
    """
    Verify that the receiver correctly handles multihop jobs which fail
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'all_vos': True, 'total_threads': 1})
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
        did = did_factory.random_file_did()
        replica_client.add_replicas(rse=src_rse, files=[{'scope': did['scope'].external, 'name': did['name'], 'bytes': 1, 'adler32': 'aaaaaaaa'}])

        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

        request = __wait_for_state_transition(dst_rse_id=jump_rse_id, run_poller=False, **did)
        assert request['state'] == RequestState.FAILED
        request = __wait_for_state_transition(dst_rse_id=dst_rse_id, run_poller=False, **did)
        assert request['state'] == RequestState.FAILED
        assert 'Unused hop in multi-hop' in request['err_msg']

        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_receiver_update_request_state_total', labels={'updated': 'True'}) >= 1

        # Finisher will handle transfers of the same multihop one hop at a time
        finisher(once=True, partition_wait_time=0)
        finisher(once=True, partition_wait_time=0)
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
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.RECEIVER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
]}], indirect=True)
def test_multihop_receiver_on_success(vo, did_factory, root_account, caches_mock, metrics_mock):
    """
    Verify that the receiver correctly handles successful multihop jobs
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'all_vos': True, 'total_threads': 1})
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
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=3600, locked=False, subscription_id=None, priority=rule_priority)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

        request = __wait_for_state_transition(dst_rse_id=jump_rse_id, run_poller=False, **did)
        assert request['state'] == RequestState.DONE
        request = __wait_for_state_transition(dst_rse_id=dst_rse_id, run_poller=False, **did)
        assert request['state'] == RequestState.DONE

        fts_response = FTS3Transfertool(external_host=TEST_FTS_HOST).bulk_query({request['external_id']: {request['id']: request}})
        fts_response = fts_response[request['external_id']][request['id']]
        assert fts_response.job_response['priority'] == rule_priority

        # Two hops; both handled by receiver
        assert metrics_mock.get_sample_value('rucio_daemons_conveyor_receiver_update_request_state_total', labels={'updated': 'True'}) >= 2
    finally:
        receiver_graceful_stop.set()
        receiver_thread.join(timeout=5)
        receiver_graceful_stop.clear()


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.RECEIVER, NoParallelGroups.POLLER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_receiver_archiving(vo, did_factory, root_account, caches_mock, scitags_mock):
    """
    Ensure that receiver doesn't mark archiving requests as DONE
    """

    src_rse = 'XRD3'
    src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
    dst_rse = 'XRD4'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)
    all_rses = [src_rse_id, dst_rse_id]

    received_messages = {}

    class ReceiverWrapper(Receiver):
        """
        Wrap receiver to record the last handled message for each given request_id
        """
        def _perform_request_update(self, msg, *, session=None, logger=logging.log):
            ret = super()._perform_request_update(msg, session=session, logger=logger)
            received_messages[msg['file_metadata']['request_id']] = msg
            return ret

    with patch('rucio.daemons.conveyor.receiver.Receiver', ReceiverWrapper):
        receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'all_vos': True, 'total_threads': 1})
        receiver_thread.start()
        # Fake that destination RSE is a tape
        rse_core.update_rse(rse_id=dst_rse_id, parameters={'rse_type': RSEType.TAPE})
        try:
            rse_core.add_rse_attribute(dst_rse_id, 'archive_timeout', 60)

            did = did_factory.upload_test_file(src_rse)
            rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None, activity='test')
            submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

            # Wait for the reception of the FTS Completion message for the submitted request
            request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
            for i in range(MAX_POLL_WAIT_SECONDS):
                if request['id'] in received_messages:
                    break
                if i == MAX_POLL_WAIT_SECONDS - 1:
                    assert False  # Waited too long; fail the test
                time.sleep(1)
            assert __wait_for_fts_state(request, expected_state='ARCHIVING') == 'ARCHIVING'

            # Receiver must not mark "ARCHIVING" requests as "DONE"
            request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
            assert received_messages[request['id']].get('scitag') == 2 << 6 | 18  # 'atlas' experiment: 2; 'test' activity: 18
            assert request['state'] == RequestState.SUBMITTED
            # Poller should also correctly handle "ARCHIVING" transfers and not mark them as DONE
            poller(once=True, older_than=0, partition_wait_time=0)
            request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
            assert request['state'] == RequestState.SUBMITTED
        finally:
            rse_core.update_rse(rse_id=dst_rse_id, parameters={'rse_type': RSEType.DISK})
            rse_core.del_rse_attribute(dst_rse_id, 'archive_timeout')

            receiver_graceful_stop.set()
            receiver_thread.join(timeout=5)
            receiver_graceful_stop.clear()


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.PREPARER, NoParallelGroups.THROTTLER, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER])
@pytest.mark.parametrize("file_config_mock", [{
    "overrides": [('conveyor', 'use_preparer', 'true')]
}], indirect=True)
def test_preparer_throttler_submitter(rse_factory, did_factory, root_account, file_config_mock, metrics_mock):
    """
    Integration test of the preparer/throttler workflow.
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse1, dst_rse_id1 = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse2, dst_rse_id2 = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id1, dst_rse_id2]

    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)
    distance_core.add_distance(src_rse_id, dst_rse_id1, distance=10)
    distance_core.add_distance(src_rse_id, dst_rse_id2, distance=10)
    # Set limits only for one of the RSEs
    request_core.set_transfer_limit(dst_rse1, max_transfers=1, activity='all_activities', strategy='fifo')

    did1 = did_factory.upload_test_file(src_rse)
    did2 = did_factory.upload_test_file(src_rse)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=dst_rse1, grouping='ALL', weight=None, lifetime=3600, locked=False, subscription_id=None)
    rule_core.add_rule(dids=[did2], account=root_account, copies=1, rse_expression=dst_rse1, grouping='ALL', weight=None, lifetime=3600, locked=False, subscription_id=None)
    rule_core.add_rule(dids=[did1], account=root_account, copies=1, rse_expression=dst_rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did1)
    assert request['state'] == RequestState.PREPARING
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did2)
    assert request['state'] == RequestState.PREPARING
    request = request_core.get_request_by_did(rse_id=dst_rse_id2, **did1)
    assert request['state'] == RequestState.PREPARING

    # submitter must not work on PREPARING replicas
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    # One RSE has limits set: the requests will be moved to WAITING status; the other RSE has no limits: go directly to queued
    preparer(once=True, sleep_time=1, bulk=100, partition_wait_time=0, ignore_availability=False)
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did1)
    assert request['state'] == RequestState.WAITING
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **did2)
    assert request['state'] == RequestState.WAITING
    request = request_core.get_request_by_did(rse_id=dst_rse_id2, **did1)
    assert request['state'] == RequestState.QUEUED

    # submitter must not work on WAITING replicas
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    # One of the waiting requests will be queued, the second will remain in waiting state
    throttler(once=True, partition_wait_time=0)
    # Check metrics.
    # This gauge values are recorded at the beginning of the execution. Hence 2 waiting and 0 transfers
    gauge_name = 'rucio_daemons_conveyor_throttler_rse_transfer_limits'
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'residual_capacity'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'max_transfers'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'active'}) == 0
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'waiting'}) == 2
    request1 = request_core.get_request_by_did(rse_id=dst_rse_id1, **did1)
    request2 = request_core.get_request_by_did(rse_id=dst_rse_id1, **did2)
    # one request WAITING and other QUEUED
    assert (request1['state'] == RequestState.WAITING and request2['state'] == RequestState.QUEUED
            or request1['state'] == RequestState.QUEUED and request2['state'] == RequestState.WAITING)
    waiting_did = did1 if request1['state'] == RequestState.WAITING else did2
    queued_did = did1 if request1['state'] == RequestState.QUEUED else did2

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    # Calling the throttler again will not schedule the waiting request, because there is a submitted one
    throttler(once=True, partition_wait_time=0)
    # This gauge values are recorded at the beginning of the execution. Hence 1 waiting and one transfer
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'residual_capacity'}) == 0
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'max_transfers'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'active'}) == 1
    assert metrics_mock.get_sample_value(gauge_name, labels={'activity': 'all_activities', 'rse': dst_rse1, 'limit_attr': 'waiting'}) == 1
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **waiting_did)
    assert request['state'] == RequestState.WAITING

    request = __wait_for_state_transition(dst_rse_id=dst_rse_id1, **queued_did)
    assert request['state'] == RequestState.DONE
    request = __wait_for_state_transition(dst_rse_id=dst_rse_id2, **did1)
    assert request['state'] == RequestState.DONE

    # Now that the submitted transfers are finished, the WAITING one can be queued
    throttler(once=True, partition_wait_time=0)
    request = request_core.get_request_by_did(rse_id=dst_rse_id1, **waiting_did)
    assert request['state'] == RequestState.QUEUED

    # Check that resetting stale waiting requests works properly
    request_core.set_transfer_limit(dst_rse2, max_transfers=1, activity='all_activities', strategy='fifo')
    did3 = did_factory.upload_test_file(src_rse)
    did4 = did_factory.upload_test_file(src_rse)
    rule_core.add_rule(dids=[did3], account=root_account, copies=1, rse_expression=dst_rse2, grouping='ALL',
                       weight=None, lifetime=3600, locked=False, subscription_id=None)
    rule_core.add_rule(dids=[did4], account=root_account, copies=1, rse_expression=dst_rse2, grouping='ALL',
                       weight=None, lifetime=3600, locked=False, subscription_id=None)
    request3 = request_core.get_request_by_did(rse_id=dst_rse_id2, **did3)
    request4 = request_core.get_request_by_did(rse_id=dst_rse_id2, **did4)
    assert request3['state'] == RequestState.PREPARING
    assert request4['state'] == RequestState.PREPARING

    # Run the preparer so requests are in waiting state
    preparer(once=True, sleep_time=1, bulk=100, partition_wait_time=0, ignore_availability=False)
    request3 = request_core.get_request_by_did(rse_id=dst_rse_id2, **did3)
    request4 = request_core.get_request_by_did(rse_id=dst_rse_id2, **did4)
    assert request3['state'] == RequestState.WAITING
    assert request4['state'] == RequestState.WAITING

    # Artificially set both requests' last_processed_at timestamp as >1 day old
    @transactional_session
    def __set_process_timestamp(request_ids, timestamp, *, session=None):
        stmt = update(
            models.Request
        ).where(
            models.Request.id.in_(request_ids)
        ).values(
            {
                models.Request.last_processed_at: timestamp
            }
        )
        session.execute(stmt)

    __set_process_timestamp([request['id'] for request in [request3, request4]], datetime.utcnow() - timedelta(days=2))

    # Run throttler: one request reset to PREPARING state and Null source_rse_id, and one request QUEUED
    throttler(once=True, partition_wait_time=0)
    request3 = request_core.get_request_by_did(rse_id=dst_rse_id2, **did3)
    request4 = request_core.get_request_by_did(rse_id=dst_rse_id2, **did4)

    assert ((request3['source_rse_id'] is None and request3['state'] == RequestState.PREPARING and request4['state'] == RequestState.QUEUED)
            or (request4['source_rse_id'] is None and request4['state'] == RequestState.PREPARING and request3['state'] == RequestState.QUEUED))


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
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
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

        replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
        assert replica['state'] == ReplicaState.AVAILABLE
    finally:
        rse_core.update_rse(rse_id=dst_rse_id, parameters={'deterministic': True})


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.STAGER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
def test_stager(rse_factory, did_factory, root_account, replica_client):
    """
    Submit a real transfer to FTS and rely on the gfal "mock" plugin to report a simulated "success"
    https://gitlab.cern.ch/dmc/gfal2/-/blob/master/src/plugins/mock/README_PLUGIN_MOCK
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id]

    distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
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
                                           'requested_at': datetime.utcnow()}])
    stager(once=True, rses=[{'id': rse_id} for rse_id in all_rses])

    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, max_wait_seconds=2 * MAX_POLL_WAIT_SECONDS, **did)
    assert replica['state'] == ReplicaState.AVAILABLE


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.FINISHER])
def test_transfer_to_mas_existing_replica(rse_factory, did_factory, root_account, jdoe_account):
    """
    Test qos: transfer from tape to disk
    Assert rse maximum_pin_lifetime is passed to transfer tool in the transfer request
    Test rule and lock state transitions
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.DISK)
    all_rses = [src_rse_id, dst_rse_id]

    maximum_pin_lifetime = 86400

    distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
    rse_core.add_rse_attribute(dst_rse_id, 'staging_required', True)
    rse_core.add_rse_attribute(dst_rse_id, 'maximum_pin_lifetime', maximum_pin_lifetime)

    did = did_factory.upload_test_file(rse_name=src_rse)

    rule1_id = rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=-1, locked=False, subscription_id=None)[0]
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    assert request['request_type'] == RequestType.TRANSFER

    submitter(once=True, rses=[{'id': dst_rse_id}], partition_wait_time=0, transfertools=['mock'], transfertype='single', filter_transfertool=None)

    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule1_id)[0]['state'] == LockState.REPLICATING
    assert rule_core.get_rule(rule1_id)['state'] == RuleState.REPLICATING

    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, transfertool='mock', **did)
    assert replica['state'] == ReplicaState.AVAILABLE

    assert rule_core.get_rule(rule1_id)['state'] == RuleState.OK

    # assert all replicas available
    for rse_id in all_rses:
        assert replica_core.get_replica(rse_id=rse_id, **did)['state'] == ReplicaState.AVAILABLE

    # now test a second rule, different account
    set_local_account_limit(jdoe_account, dst_rse_id, bytes_=-1)
    rule2_id = rule_core.add_rule(dids=[did], account=jdoe_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=-1, locked=False, subscription_id=None, source_replica_expression=dst_rse)[0]
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    assert request['request_type'] == RequestType.STAGEIN

    stager(once=True, rses=[{'id': dst_rse_id}])

    assert request['attributes']['lifetime'] == str(maximum_pin_lifetime)
    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule2_id)[0]['state'] == LockState.REPLICATING
    assert rule_core.get_rule(rule2_id)['state'] == RuleState.REPLICATING

    # mock a successful stagein
    request = request_core.get_request(request_id=request['id'])
    request_core.transition_request_state(request_id=request['id'], state=RequestState.DONE, external_id=request['external_id'])
    finisher(once=True, partition_wait_time=0)

    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule1_id)[0]['state'] == LockState.OK
    assert rule_core.get_rule(rule1_id)['state'] == RuleState.OK
    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule2_id)[0]['state'] == LockState.OK
    assert rule_core.get_rule(rule2_id)['state'] == RuleState.OK


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
def test_failed_transfers_to_mas_existing_replica(rse_factory, did_factory, root_account, jdoe_account):
    """
    Test qos: transfer from tape to disk
    Assert rse maximum_pin_lifetime is passed to transfer tool in the transfer request
    Test rule and lock state transitions
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.DISK)

    maximum_pin_lifetime = 86400

    distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
    rse_core.add_rse_attribute(dst_rse_id, 'staging_required', True)
    rse_core.add_rse_attribute(dst_rse_id, 'maximum_pin_lifetime', maximum_pin_lifetime)

    did = did_factory.upload_test_file(rse_name=src_rse)

    rule1_id = rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=-1, locked=False, subscription_id=None)[0]
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    assert request['request_type'] == RequestType.TRANSFER

    submitter(once=True, rses=[{'id': dst_rse_id}], partition_wait_time=0, transfertools=['mock'], transfertype='single', filter_transfertool=None)

    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule1_id)[0]['state'] == LockState.REPLICATING
    assert rule_core.get_rule(rule1_id)['state'] == RuleState.REPLICATING

    # mock a failed transfer
    request = request_core.get_request(request_id=request['id'])
    request_core.transition_request_state(request_id=request['id'], state=RequestState.FAILED, external_id=request['external_id'])
    finisher(once=True, partition_wait_time=0)
    lock_core.failed_transfer(scope=did['scope'], name=did['name'], rse_id=dst_rse_id)

    assert rule_core.get_rule(rule1_id)['state'] == RuleState.STUCK
    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule1_id)[0]['state'] == LockState.STUCK

    # now test a second rule, different account
    set_local_account_limit(jdoe_account, dst_rse_id, bytes_=-1)
    rule2_id = rule_core.add_rule(dids=[did], account=jdoe_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=-1, locked=False, subscription_id=None, source_replica_expression=dst_rse)[0]
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    # since the first rule is STUCK assert a transfer not stagein
    assert request['request_type'] == RequestType.TRANSFER

    submitter(once=True, rses=[{'id': dst_rse_id}], partition_wait_time=0, transfertools=['mock'], transfertype='single', filter_transfertool=None)

    assert request['attributes']['lifetime'] is None
    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule2_id)[0]['state'] == LockState.REPLICATING
    assert rule_core.get_rule(rule2_id)['state'] == RuleState.REPLICATING

    # mock a failed transfer for the second rule
    request = request_core.get_request(request_id=request['id'])
    request_core.transition_request_state(request_id=request['id'], state=RequestState.FAILED, external_id=request['external_id'])
    finisher(once=True, partition_wait_time=0)
    lock_core.failed_transfer(scope=did['scope'], name=did['name'], rse_id=dst_rse_id)

    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule1_id)[0]['state'] == LockState.STUCK
    assert rule_core.get_rule(rule1_id)['state'] == RuleState.STUCK
    assert lock_core.get_replica_locks_for_rule_id(rule_id=rule2_id)[0]['state'] == LockState.STUCK
    assert rule_core.get_rule(rule2_id)['state'] == RuleState.STUCK


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
def test_lost_transfers(rse_factory, did_factory, root_account):
    """
    Correctly handle FTS "404 not found" errors.
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id]

    distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

    did = did_factory.upload_test_file(src_rse)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    # Fake that the transfer is submitted and lost
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    __update_request(request['id'], external_id='some-fake-random-id')

    # The request must be marked lost
    request = __wait_for_state_transition(dst_rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.LOST

    # Set update time far in the past to bypass protections (not resubmitting too fast).
    # Run finisher and submitter, the request must be resubmitted and transferred correctly
    __update_request(request['id'], updated_at=datetime.utcnow() - timedelta(days=1))
    finisher(once=True, partition_wait_time=0)
    # The source ranking must not be updated for submission failures and lost transfers
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert __get_source(request_id=request['id'], src_rse_id=src_rse_id, **did).ranking == 0
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER])
def test_cancel_rule(rse_factory, did_factory, root_account):
    """
    Ensure that, when we cancel a rule, the request is cancelled in FTS
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse_id]

    distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

    did = did_factory.upload_test_file(src_rse)

    [rule_id] = rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    class _FTSWrapper(FTSWrapper):
        @staticmethod
        def on_submit(file):
            # Simulate using the mock gfal plugin that it takes a long time to copy the file
            file['sources'] = [set_query_parameters(s_url, {'time': 30}) for s_url in file['sources']]

    with patch('rucio.core.transfer.TRANSFERTOOL_CLASSES_BY_NAME', new={'fts3': _FTSWrapper}):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    rule_core.delete_rule(rule_id)

    with pytest.raises(RequestNotFound):
        request_core.get_request_by_did(rse_id=dst_rse_id, **did)

    fts_response = FTS3Transfertool(external_host=TEST_FTS_HOST).bulk_query({request['external_id']: {request['id']: request}})
    assert fts_response[request['external_id']][request['id']].job_response['job_state'] == 'CANCELED'


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

    def _file_from_transfer(self, transfer, job_params):
        file = super()._file_from_transfer(transfer, job_params)
        self.on_submit(file)
        return file

    def _FTS3Transfertool__bulk_query_responses(self, jobs_response, requests_by_eid):
        self.on_receive(jobs_response)
        return super()._FTS3Transfertool__bulk_query_responses(jobs_response, requests_by_eid)


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
        did = did_factory.random_file_did()
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
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_overwrite_on_tape(overwrite_on_tape_topology, caches_mock):
    """
    Ensure that overwrite is not set for transfers towards TAPE RSEs
    """
    rse1_id, rse2_id, rse3_id, did1, did2 = overwrite_on_tape_topology(did1_corrupted=False, did2_corrupted=True)
    all_rses = [rse1_id, rse2_id, rse3_id]

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    request = __wait_for_state_transition(dst_rse_id=rse3_id, **did1)
    assert request['state'] == RequestState.FAILED
    assert 'Destination file exists and overwrite is not enabled' in request['err_msg']
    request = __wait_for_state_transition(dst_rse_id=rse3_id, **did2)
    assert request['state'] == RequestState.FAILED
    assert 'Destination file exists and overwrite is not enabled' in request['err_msg']


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_overwrite_hops(overwrite_on_tape_topology, caches_mock, did_factory, file_factory):
    """
    Ensure that we request overwrite of intermediate hops on multi-hop transfers towards TAPE RSEs
    """
    rse1_id, rse2_id, rse3_id, did1, did2 = overwrite_on_tape_topology(did1_corrupted=False, did2_corrupted=True)
    did_factory.upload_client.upload(
        [
            {
                'path': file_factory.file_generator(size=3),
                'rse': rse_core.get_rse_name(rse2_id),
                'did_scope': did1['scope'].external,
                'did_name': did1['name'],
                'no_register': True,
            }
        ]
    )
    all_rses = [rse1_id, rse2_id, rse3_id]

    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    fts_schema_version = FTS3Transfertool(external_host=TEST_FTS_HOST).version()['schema']['major']
    if fts_schema_version >= 8:
        # Newer fts version will honor the overwrite_hop
        request = __wait_for_state_transition(dst_rse_id=rse2_id, **did1)
        assert request['state'] == RequestState.DONE
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.FAILED
        assert 'Destination file exists and overwrite is not enabled' in request['err_msg']
    else:
        # FTS only recently introduced the overwrite_hops parameter. It will be ignored on old
        # fts versions and the first hop will fail with the  file exists error
        # TODO: remove this else after FTS 3.12 release and after updating rucio/fts container with the new release
        request = __wait_for_state_transition(dst_rse_id=rse2_id, **did1)
        assert request['state'] == RequestState.FAILED
        assert 'Destination file exists and overwrite is not enabled' in request['err_msg']
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.FAILED
        assert 'Unused hop in multi-hop' in request['err_msg']


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse.REGION',
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config.REGION',
    'rucio.rse.rsemanager.RSE_REGION',  # for RSE info
]}], indirect=True)
def test_file_exists_handled(overwrite_on_tape_topology, caches_mock):
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

    with patch('rucio.daemons.conveyor.poller.FTS3Transfertool', _FTSWrapper):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)

        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.DONE
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.DONE


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers; leaves pending fts transfers in archiving state")
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'overwrite_corrupted_files', False)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
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

    with patch('rucio.daemons.conveyor.poller.FTS3Transfertool', _FTSWrapper):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
        # Both transfers must be marked as failed because the file size is incorrect
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.FAILED
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.FAILED

        # Re-submit the failed requests. They must fail again, because overwrite_corrupted_files is False
        # 2 runs: for multihop, finisher works one hop at a time
        finisher(once=True, partition_wait_time=0)
        finisher(once=True, partition_wait_time=0)
        request = request_core.get_request_by_did(rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.QUEUED
        request = request_core.get_request_by_did(rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.QUEUED
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
        # Set overwrite to True before running the poller or finisher
        core_config.set('transfers', 'overwrite_corrupted_files', True)
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.FAILED
        request = __wait_for_state_transition(dst_rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.FAILED

        # Re-submit one more time. Now the destination file must be overwritten
        finisher(once=True, partition_wait_time=0)
        finisher(once=True, partition_wait_time=0)
        request = request_core.get_request_by_did(rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.QUEUED
        request = request_core.get_request_by_did(rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.QUEUED
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
        request = request_core.get_request_by_did(rse_id=rse3_id, **did1)
        assert request['state'] == RequestState.SUBMITTED
        assert __wait_for_fts_state(request, expected_state='ARCHIVING') == 'ARCHIVING'
        request = request_core.get_request_by_did(rse_id=rse3_id, **did2)
        assert request['state'] == RequestState.SUBMITTED
        assert __wait_for_fts_state(request, expected_state='ARCHIVING') == 'ARCHIVING'


@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER])
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('conveyor', 'usercert', 'DEFAULT_DUMMY_CERT'),
    ('vo_certs', 'new', 'NEW_VO_DUMMY_CERT'),
]}], indirect=True)
def test_multi_vo_certificates(file_config_mock, rse_factory, did_factory, scope_factory, vo, second_vo, root_account):
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
        distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
        account = InternalAccount('root', vo=vo)
        did = did_factory.random_file_did(scope=scope)
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

        def bulk_query(self, requests_by_eid, timeout=None):
            certs_used_by_poller.append(self.cert[0])
            return {}

    with patch('rucio.core.transfer.TRANSFERTOOL_CLASSES_BY_NAME', new={'fts3': _FTSWrapper}):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)
        assert sorted(certs_used_by_submitter) == ['DEFAULT_DUMMY_CERT', 'NEW_VO_DUMMY_CERT']

        poller(once=True, older_than=0, partition_wait_time=0)
        assert sorted(certs_used_by_poller) == ['DEFAULT_DUMMY_CERT', 'NEW_VO_DUMMY_CERT']


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("core_config_mock", [
    {"table_content": [
        ('transfers', 'multihop_tombstone_delay', -1),  # Set OBSOLETE tombstone for intermediate replicas
        ('transfers', 'multihop_rse_expression', '*'),
    ]},
], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser.REGION',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config.REGION',
    'rucio.daemons.reaper.reaper.REGION',
]}], indirect=True)
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('transfers', 'stats_enabled', 'True'),
]}], indirect=True)
def test_two_multihops_same_intermediate_rse(rse_factory, did_factory, root_account, file_config_mock, core_config_mock, caches_mock):
    """
    Handle correctly two multihop transfers having to both jump via the same intermediate hops
    """
    # +------+    +------+    +------+    +------+    +------+
    # |      |    |      |    |      |    |      |    |      |
    # | RSE1 +--->| RSE2 +--->| RSE3 +--->| RSE4 +--->| RSE5 |
    # |      |    |      |    |      |    |      |    |      |
    # +------+    +------+    +---+--+    +------+    +------+
    #                             |
    #                             |       +------+    +------+
    #                             |       |      |    |      |
    #                             +------>| RSE6 +--->| RSE7 |
    #                                     |      |    |      |
    #                                     +------+    +------+
    start_time = datetime.utcnow()
    _, _, reaper_cache_region = caches_mock
    rse1, rse1_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse2, rse2_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse3, rse3_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse4, rse4_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse5, rse5_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse6, rse6_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse7, rse7_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [rse1_id, rse2_id, rse3_id, rse4_id, rse5_id, rse6_id, rse7_id]
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)
        rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=1)
        rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=1, free=0)
    distance_core.add_distance(rse1_id, rse2_id, distance=10)
    distance_core.add_distance(rse2_id, rse3_id, distance=10)
    distance_core.add_distance(rse3_id, rse4_id, distance=10)
    distance_core.add_distance(rse4_id, rse5_id, distance=10)
    distance_core.add_distance(rse3_id, rse6_id, distance=10)
    distance_core.add_distance(rse6_id, rse7_id, distance=10)

    did = did_factory.upload_test_file(rse1)
    rule_core.add_rule(dids=[did], account=root_account, copies=2, rse_expression=f'{rse5}|{rse7}', grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    class _FTSWrapper(FTSWrapper):
        @staticmethod
        def on_submit(file):
            # Simulate using the mock gfal plugin a transfer failure
            file['sources'] = [set_query_parameters(s_url, {'errno': 2}) for s_url in file['sources']]

    # Submit the first time, but force a failure to verify that retries are correctly handled
    with patch('rucio.core.transfer.TRANSFERTOOL_CLASSES_BY_NAME', new={'fts3': _FTSWrapper}):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    request = __wait_for_state_transition(dst_rse_id=rse2_id, **did)
    assert request['state'] == RequestState.FAILED

    # Re-submit the transfer without simulating a failure. Everything should go as normal starting now.
    for _ in range(4):
        # for multihop, finisher works one hop at a time. 4 is the maximum number of hops in this test graph
        finisher(once=True, partition_wait_time=0)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    # one request must be submitted, but the second will only be queued
    if request_core.get_request_by_did(rse_id=rse5_id, **did)['state'] == RequestState.QUEUED:
        rse_id_second_to_last_queued, rse_id_queued = rse4_id, rse5_id
        rse_id_second_to_last_submit, rse_id_submitted = rse6_id, rse7_id
    else:
        rse_id_second_to_last_queued, rse_id_queued = rse6_id, rse7_id
        rse_id_second_to_last_submit, rse_id_submitted = rse4_id, rse5_id
    request = request_core.get_request_by_did(rse_id=rse_id_queued, **did)
    assert request['state'] == RequestState.QUEUED
    request = request_core.get_request_by_did(rse_id=rse_id_submitted, **did)
    assert request['state'] == RequestState.SUBMITTED

    # Calling submitter again will not unblock the queued requests
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=rse_id_submitted, **did)
    assert replica['state'] == ReplicaState.AVAILABLE
    request = request_core.get_request_by_did(rse_id=rse_id_queued, **did)
    assert request['state'] == RequestState.QUEUED

    # Once the submitted transfer is done, the submission will continue for second request (one hop at a time)
    # First of the remaining two hops submitted
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=rse_id_second_to_last_queued, **did)
    assert replica['state'] == ReplicaState.AVAILABLE

    # One of the intermediate replicas is eligible for deletion. Others are blocked by entries in source table
    reaper_cache_region.invalidate()
    reaper(once=True, rses=[], include_rses='|'.join([rse2, rse3, rse4, rse6]), exclude_rses=None)
    with pytest.raises(ReplicaNotFound):
        replica_core.get_replica(rse_id=rse_id_second_to_last_submit, **did)
    for rse_id in [rse2_id, rse3_id, rse_id_second_to_last_queued]:
        replica_core.get_replica(rse_id=rse_id, **did)

    # Final hop
    __update_request(request_core.get_request_by_did(rse_id=rse_id_queued, **did)['id'], last_processed_by=None)
    submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=0, transfertype='single', filter_transfertool=None)
    replica = __wait_for_replica_transfer(dst_rse_id=rse_id_queued, **did)
    assert replica['state'] == ReplicaState.AVAILABLE

    # All intermediate replicas can be deleted
    reaper_cache_region.invalidate()
    reaper(once=True, rses=[], include_rses='|'.join([rse2, rse3, rse4, rse6]), exclude_rses=None)
    for rse_id in [rse2_id, rse3_id, rse4_id, rse6_id]:
        with pytest.raises(ReplicaNotFound):
            replica_core.get_replica(rse_id=rse_id, **did)

    # Verify that the statistics are correctly recorded for executed transfers
    stats_manager = request_core.TransferStatsManager()
    dict_stats = {}
    for stat in stats_manager.load_totals(
            older_t=start_time - stats_manager.raw_resolution
    ):
        dict_stats.setdefault(stat['dest_rse_id'], {})[stat['src_rse_id']] = stat
    assert dict_stats[rse2_id][rse1_id]['files_failed'] == 1
    assert dict_stats[rse2_id][rse1_id]['files_done'] == 1
    assert dict_stats[rse2_id][rse1_id]['bytes_done'] == 2


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER])
def test_checksum_validation(rse_factory, did_factory, root_account):
    """
    Ensure that the correct checksum validation strategy is applied on submission
    """
    src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse1, dst_rse1_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse2, dst_rse2_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    dst_rse3, dst_rse3_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    all_rses = [src_rse_id, dst_rse1_id, dst_rse2_id, dst_rse3_id]

    for rse_id in [dst_rse1_id, dst_rse2_id, dst_rse3_id]:
        distance_core.add_distance(src_rse_id, rse_id, distance=10)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

    rse_core.add_rse_attribute(src_rse_id, 'supported_checksums', 'adler32')
    rse_core.add_rse_attribute(dst_rse1_id, 'verify_checksum', False)
    rse_core.add_rse_attribute(dst_rse2_id, 'supported_checksums', 'md5')
    rse_core.add_rse_attribute(dst_rse3_id, 'supported_checksums', 'md5,adler32')

    did = did_factory.upload_test_file(src_rse)
    replica = replica_core.get_replica(rse_id=src_rse_id, **did)

    rule_core.add_rule(dids=[did], account=root_account, copies=3, rse_expression=f'{dst_rse1}|{dst_rse2}|{dst_rse3}', grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    class _FTSWrapper(FTSWrapper):
        @staticmethod
        def on_submit(file):
            # Set the correct checksum on source and simulate a wrong checksum on destination
            file['sources'] = [set_query_parameters(s_url, {'checksum': replica['adler32']}) for s_url in file['sources']]
            file['destinations'] = [set_query_parameters(d_url, {'checksum': 'randomString2'}) for d_url in file['destinations']]

    with patch('rucio.core.transfer.TRANSFERTOOL_CLASSES_BY_NAME', new={'fts3': _FTSWrapper}):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)

    # Checksum verification disabled on this rse, so the transfer must use source validation and succeed
    request = __wait_for_state_transition(dst_rse_id=dst_rse1_id, **did)
    assert request['state'] == RequestState.DONE

    # No common supported checksum between the source and destination rse. It will verify the destination rse checksum and fail
    request = __wait_for_state_transition(dst_rse_id=dst_rse2_id, **did)
    assert request['state'] == RequestState.FAILED
    assert 'User and destination checksums do not match' in request['err_msg']

    # Common checksum exists between the two. It must use "both" validation strategy and fail
    request = __wait_for_state_transition(dst_rse_id=dst_rse3_id, **did)
    assert 'Source and destination checksums do not match' in request['err_msg']
    assert request['state'] == RequestState.FAILED


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.RECEIVER])
@pytest.mark.parametrize("file_config_mock", [
    {"overrides": [('oidc', 'admin_issuer', 'indigoiam')]},
], indirect=True)
def test_transfer_with_tokens(vo, did_factory, root_account, caches_mock, file_config_mock):
    src_rse = 'WEB1'
    src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
    dst_rse = 'XRD5'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)
    all_rses = [src_rse_id, dst_rse_id]

    did = did_factory.upload_test_file(src_rse)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    received_messages = {}

    class ReceiverWrapper(Receiver):
        """
        Wrap receiver to record the last handled message for each given request_id
        """
        def _perform_request_update(self, msg, *, session=None, logger=logging.log):
            ret = super()._perform_request_update(msg, session=session, logger=logger)
            received_messages[msg['file_metadata']['request_id']] = msg
            return ret

    with patch('rucio.daemons.conveyor.receiver.Receiver', ReceiverWrapper):
        receiver_thread = threading.Thread(target=receiver, kwargs={'id_': 0, 'all_vos': True, 'total_threads': 1})
        receiver_thread.start()
        try:
            submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertype='single', filter_transfertool=None)
            # Wait for the reception of the FTS Completion message for the submitted request
            request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
            for i in range(MAX_POLL_WAIT_SECONDS):
                if request['id'] in received_messages:
                    break
                if i == MAX_POLL_WAIT_SECONDS - 1:
                    assert False  # Waited too long; fail the test
                time.sleep(1)
            assert received_messages[request['id']]['job_metadata']['auth_method'] == 'oauth2'
        finally:
            receiver_graceful_stop.set()
            receiver_thread.join(timeout=5)
            receiver_graceful_stop.clear()


@pytest.mark.noparallel(groups=[NoParallelGroups.PREPARER])
@pytest.mark.parametrize("file_config_mock", [{
    "overrides": [('conveyor', 'use_preparer', 'true')]
}], indirect=True)
def test_preparer_ignore_availability(rse_factory, did_factory, root_account, file_config_mock):
    """
    Integration test of the preparer/throttler workflow.
    """

    def __setup_test():
        src_rse, src_rse_id = rse_factory.make_posix_rse()
        dst_rse, dst_rse_id = rse_factory.make_posix_rse()

        distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
        for rse_id in [src_rse_id, dst_rse_id]:
            rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)
        did = did_factory.upload_test_file(src_rse)
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        rse_core.update_rse(src_rse_id, {'availability_read': False})

        return src_rse_id, dst_rse_id, did

    src_rse_id, dst_rse_id, did = __setup_test()
    preparer(once=True, sleep_time=1, bulk=100, partition_wait_time=0, ignore_availability=False)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.NO_SOURCES

    src_rse_id, dst_rse_id, did = __setup_test()
    preparer(once=True, sleep_time=1, bulk=100, partition_wait_time=0, ignore_availability=True)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
    assert request['state'] == RequestState.QUEUED


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.PREPARER, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("file_config_mock", [
    {
        "overrides": [
            ("transfers", "fts3tape_metadata_plugins", "activity"),
            ('tape_priority', 'fast', '100'),
            ('tape_priority', 'slow', '1')
        ]
    }
], indirect=True)
def test_transfer_plugins(rse_factory, did_factory, root_account, file_config_mock):
    """
        Add existing plugin to fts3 transfertool, verify submission goes through.
    """
    def __setup_test():
        src_rse, src_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)
        dst_rse, dst_rse_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)

        distance_core.add_distance(src_rse_id, dst_rse_id, distance=10)
        rse_core.add_rse_attribute(dst_rse_id, 'verify_checksum', False)

        for rse_id in [src_rse_id, dst_rse_id]:
            rse_core.add_rse_attribute(rse_id, 'fts', TEST_FTS_HOST)

        did_fast = did_factory.upload_test_file(src_rse)
        did_slow = did_factory.upload_test_file(src_rse)

        activity_dict = {did_fast['name']: "fast", did_slow['name']: "slow"}

        rule_core.add_rule(dids=[did_fast, did_slow], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        return src_rse_id, dst_rse_id, did_fast, did_slow, activity_dict

    src_rse_id, dst_rse_id, did_fast, did_slow, activity_dict = __setup_test()

    class _Fts3PluginTestWrapper(FTS3Transfertool):
        def _file_from_transfer(self, transfer, job_params):
            transfer.rws.activity = activity_dict[transfer.rws.name]
            super()._file_from_transfer(transfer, job_params)

    preparer(once=True, sleep_time=1, bulk=2, partition_wait_time=0, ignore_availability=False)
    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did_fast)
    assert request['state'] == RequestState.QUEUED

    request = request_core.get_request_by_did(rse_id=dst_rse_id, **did_slow)
    assert request['state'] == RequestState.QUEUED

    with patch("rucio.transfertool.fts3.FTS3Transfertool", _Fts3PluginTestWrapper):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in (src_rse_id, dst_rse_id)], group_bulk=1, partition_wait_time=0, transfertools=['fts3'], transfertype='single')

    # Verify that both the submission works
    request_fast = request_core.get_request_by_did(rse_id=dst_rse_id, **did_fast)
    request_slow = request_core.get_request_by_did(rse_id=dst_rse_id, **did_slow)

    # Does not impact the actual prority of the transfer - is read by placement algorithm not fts3.
    assert request_fast['state'] != RequestState.SUBMISSION_FAILED
    assert request_slow['state'] != RequestState.SUBMISSION_FAILED
    assert request_fast['state'] != RequestState.FAILED
    assert request_slow['state'] != RequestState.FAILED


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(groups=[NoParallelGroups.XRD, NoParallelGroups.SUBMITTER, NoParallelGroups.POLLER, NoParallelGroups.FINISHER])
@pytest.mark.parametrize("file_config_mock", [{
    "overrides": [('client', 'register_bittorrent_meta', 'true')]
}], indirect=True)
def test_bittorrent_submission(did_factory, root_account, vo, download_client, file_config_mock):
    src_rse = 'WEB1'
    src_rse_id = rse_core.get_rse_id(rse=src_rse, vo=vo)
    dst_rse = 'XRD5'
    dst_rse_id = rse_core.get_rse_id(rse=dst_rse, vo=vo)
    all_rses = [src_rse_id, dst_rse_id]

    did = did_factory.upload_test_file(src_rse)

    rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    mocked_credentials = {
        src_rse_id: {
            "qbittorrent_username": "rucio",
            "qbittorrent_password": "rucio90df"
        },
        dst_rse_id: {
            "qbittorrent_username": "rucio",
            "qbittorrent_password": "rucio90df"
        }
    }
    with patch('rucio.transfertool.bittorrent_driver_qbittorrent.get_rse_credentials', return_value=mocked_credentials):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=0, transfertools=['bittorrent'], filter_transfertool=None)
        request = request_core.get_request_by_did(rse_id=dst_rse_id, **did)
        assert request['state'] == RequestState.SUBMITTED

        replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, max_wait_seconds=MAX_POLL_WAIT_SECONDS, transfertool='bittorrent', **did)
        assert replica['state'] == ReplicaState.AVAILABLE

    with TemporaryDirectory() as tmp_dir:
        download_client.download_dids([{
            'did': '{scope}:{name}'.format(**did),
            'base_dir': tmp_dir,
            'rse': dst_rse,
            'no_subdir': True,
        }])
        assert adler32(f'{tmp_dir}/{did["name"]}') == did_core.get_did(**did)['adler32']
