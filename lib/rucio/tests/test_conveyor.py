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
import threading
import time
from datetime import datetime
from unittest.mock import patch
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import pytest

import rucio.daemons.reaper.reaper
from rucio.common.exception import ReplicaNotFound
from rucio.core import distance as distance_core
from rucio.core import replica as replica_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.core import transfer as transfer_core
from rucio.daemons.conveyor.finisher import finisher
from rucio.daemons.conveyor.poller import poller
from rucio.daemons.conveyor.submitter import submitter
from rucio.daemons.conveyor.stager import stager
from rucio.daemons.conveyor.receiver import receiver, graceful_stop as receiver_graceful_stop
from rucio.daemons.reaper.reaper import reaper
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, RequestType, ReplicaState, RSEType
from rucio.db.sqla.session import read_session, transactional_session
from rucio.tests.common import skip_rse_tests_with_accounts

MAX_POLL_WAIT_SECONDS = 60


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


def __wait_for_request_state(dst_rse_id, scope, name, state, max_wait_seconds=MAX_POLL_WAIT_SECONDS, run_poller=True):
    """
    Wait for the request state to be updated to the given expected state as a result of a pending transfer
    """
    request = None
    for _ in range(max_wait_seconds):
        if run_poller:
            poller(once=True, older_than=0, partition_wait_time=None)
        request = request_core.get_request_by_did(rse_id=dst_rse_id, scope=scope, name=name)
        if request['state'] == state:
            break
        time.sleep(1)
    return request


def set_query_parameters(url, params):
    """
    Set a query parameter in an url which may, or may not, have other existing query parameters
    """
    url_parts = list(urlparse(url))

    query = dict(parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urlencode(query)

    return urlunparse(url_parts)


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher; changes XRD3 usage and limits")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
    ('transfers', 'multihop_tombstone_delay', -1),  # Set OBSOLETE tombstone for intermediate replicas
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
    'rucio.daemons.reaper.reaper',
]}], indirect=True)
def test_multihop_intermediate_replica_lifecycle(vo, did_factory, root_account, core_config_mock, caches_mock):
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

        # The intermediate replica is protected by an entry in the sources table
        # Reaper must not remove this replica, even if it has an obsolete tombstone
        rucio.daemons.reaper.reaper.REGION.invalidate()
        reaper(once=True, rses=[], include_rses=jump_rse_name, exclude_rses=None)
        replica = replica_core.get_replica(rse_id=jump_rse_id, **did)
        assert replica

        # FTS fails the second transfer, so run submitter again to copy from jump rse to destination rse
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], partition_wait_time=None, transfertype='single', filter_transfertool=None)

        # Wait for the destination replica to become ready
        replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
        assert replica['state'] == ReplicaState.AVAILABLE

        rucio.daemons.reaper.reaper.REGION.invalidate()
        reaper(once=True, rses=[], include_rses='test_container_xrd=True', exclude_rses=None)

        with pytest.raises(ReplicaNotFound):
            replica_core.get_replica(rse_id=jump_rse_id, **did)
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
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
]}], indirect=True)
def test_fts_non_recoverable_failures_handled_on_multihop(vo, did_factory, root_account, replica_client, core_config_mock, caches_mock):
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
    assert request['state'] == RequestState.FAILED
    request = request_core.get_request_by_did(rse_id=jump_rse_id, **did)
    assert request['state'] == RequestState.FAILED


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
]}], indirect=True)
def test_fts_recoverable_failures_handled_on_multihop(vo, did_factory, root_account, replica_client, file_factory, core_config_mock, caches_mock):
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


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter, poller and finisher")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True),
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
]}], indirect=True)
def test_multisource(vo, did_factory, root_account, replica_client, core_config_mock, caches_mock):
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

    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE
    assert not __source_exists(src_rse_id=src_rse1_id, **did)
    assert not __source_exists(src_rse_id=src_rse2_id, **did)


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(reason="uses predefined RSEs; runs submitter and receiver")
def test_multisource_receiver(vo, did_factory, replica_client, root_account):
    """
    Run receiver as a background thread to automatically handle fts notifications.
    Ensure that a multi-source job in which the first source fails is correctly handled by receiver.
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id': 0, 'full_mode': True, 'all_vos': True, 'total_threads': 1})
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
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
]}], indirect=True)
def test_multihop_receiver_on_failure(vo, did_factory, replica_client, root_account, core_config_mock, caches_mock):
    """
    Verify that the receiver correctly handles multihop jobs which fail
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id': 0, 'full_mode': True, 'all_vos': True, 'total_threads': 1})
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
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by rse expression
    'rucio.core.config',
]}], indirect=True)
def test_multihop_receiver_on_success(vo, did_factory, root_account, core_config_mock, caches_mock):
    """
    Verify that the receiver correctly handles successful multihop jobs
    """
    receiver_thread = threading.Thread(target=receiver, kwargs={'id': 0, 'full_mode': True, 'all_vos': True, 'total_threads': 1})
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
        rule_core.add_rule(dids=[did], account=root_account, copies=1, rse_expression=dst_rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=2, partition_wait_time=None, transfertype='single', filter_transfertool=None)

        request = __wait_for_request_state(dst_rse_id=jump_rse_id, state=RequestState.DONE, run_poller=False, **did)
        assert request['state'] == RequestState.DONE
        request = __wait_for_request_state(dst_rse_id=dst_rse_id, state=RequestState.DONE, run_poller=False, **did)
        assert request['state'] == RequestState.DONE
    finally:
        receiver_graceful_stop.set()
        receiver_thread.join(timeout=5)
        receiver_graceful_stop.clear()


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
        rse_core.add_rse_attribute(rse_id, 'fts', 'https://fts:8446')

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

    replica = __wait_for_replica_transfer(dst_rse_id=dst_rse_id, **did)
    assert replica['state'] == ReplicaState.AVAILABLE


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason="runs submitter and poller;")
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('transfers', 'use_multihop', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.rse_expression_parser',  # The list of multihop RSEs is retrieved by an expression
    'rucio.core.config',
]}], indirect=True)
def test_overwrite_on_tape(rse_factory, did_factory, root_account, core_config_mock, caches_mock):
    """
    Ensure that overwrite is not set for transfers towards TAPE RSEs

    Submit a real transfer to FTS and rely on the gfal "mock" plugin to trigger a failure. The failure is triggered
    when gfal_stat is called on the destination URL and it returns a result. To achieve this via the mock
    plugin, it's enough to have a mock:// protocol/scheme and add size_pre=<something> url parameter.
    https://gitlab.cern.ch/dmc/gfal2/-/blob/master/src/plugins/mock/README_PLUGIN_MOCK
    """
    # +------+    +------+    +------+
    # |      |    |      |    |      |
    # | RSE1 +--->| RSE2 |--->| RSE3 |
    # |      |    |      |    |(tape)|
    # +------+    +------+    +------+
    rse1, rse1_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse2, rse2_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default')
    rse3, rse3_id = rse_factory.make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.posix.Default', rse_type=RSEType.TAPE)
    all_rses = [rse1_id, rse2_id, rse3_id]

    distance_core.add_distance(rse1_id, rse2_id, ranking=10)
    distance_core.add_distance(rse2_id, rse3_id, ranking=10)
    rse_core.add_rse_attribute(rse2_id, 'available_for_multihop', True)
    for rse_id in all_rses:
        rse_core.add_rse_attribute(rse_id, 'fts', 'https://fts:8446')

    # multihop transfer:
    did1 = did_factory.upload_test_file(rse1)
    # direct transfer:
    did2 = did_factory.upload_test_file(rse2)

    rule_core.add_rule(dids=[did1, did2], account=root_account, copies=1, rse_expression=rse3, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    # Wrap dest url generation to add size_pre=2 query parameter
    non_mocked_dest_url = transfer_core.DirectTransferDefinition._dest_url

    def mocked_dest_url(cls, *args):
        return set_query_parameters(non_mocked_dest_url(*args), {'size_pre': 2})

    with patch('rucio.core.transfer.DirectTransferDefinition._dest_url', new=mocked_dest_url):
        submitter(once=True, rses=[{'id': rse_id} for rse_id in all_rses], group_bulk=10, partition_wait_time=None, transfertype='single', filter_transfertool=None)

    request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did1)
    assert request['state'] == RequestState.FAILED
    request = __wait_for_request_state(dst_rse_id=rse3_id, state=RequestState.FAILED, **did2)
    assert request['state'] == RequestState.FAILED
    assert 'Destination file exists and overwrite is not enabled' in request['err_msg']
