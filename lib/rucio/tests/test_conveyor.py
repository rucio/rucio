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
import time
from datetime import datetime

import pytest

import rucio.daemons.reaper.reaper
from rucio.common.exception import ReplicaNotFound
from rucio.core import replica as replica_core
from rucio.core import request as request_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.daemons.conveyor.finisher import finisher
from rucio.daemons.conveyor.poller import poller
from rucio.daemons.conveyor.submitter import submitter
from rucio.daemons.reaper.reaper import reaper
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, ReplicaState
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import skip_rse_tests_with_accounts


def __wait_for_replica_transfer(dst_rse_id, scope, name, max_wait_seconds=60):
    """
    Wait for the replica to become AVAILABLE on the given RSE as a result of a pending transfer
    """
    replica = None
    for _ in range(max_wait_seconds):
        poller(once=True, older_than=0, partition_wait_time=None)
        finisher(once=True, partition_wait_time=None)
        replica = replica_core.get_replica(rse_id=dst_rse_id, scope=scope, name=name)
        if replica['state'] == ReplicaState.AVAILABLE:
            break
        time.sleep(1)
    return replica


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
