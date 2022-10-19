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

from datetime import datetime, timedelta

import pytest
from sqlalchemy import delete

from rucio.common.utils import generate_uuid
from rucio.core.did import attach_dids, add_did
from rucio.core.distance import add_distance
from rucio.core.replica import add_replica
from rucio.core.request import queue_requests, get_request_by_did, release_waiting_requests_per_deadline, release_all_waiting_requests, release_waiting_requests_fifo, release_waiting_requests_grouped_fifo, release_waiting_requests_per_free_volume
from rucio.core.rse import set_rse_transfer_limits
from rucio.daemons.conveyor import throttler, preparer
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, RequestType, RequestState
from rucio.tests.common import skiplimitedsql


@pytest.fixture
def connected_rse_pair(vo, rse_factory, db_session):
    source_rse, source_rse_id = rse_factory.make_mock_rse()
    dest_rse, dest_rse_id = rse_factory.make_mock_rse()
    add_distance(source_rse_id, dest_rse_id, ranking=10)

    return source_rse, source_rse_id, dest_rse, dest_rse_id


def _delete_requests(scope, names, ids=None, session=None):
    session.execute(
        delete(
            models.Request
        ).where(
            models.Request.scope == scope,
            models.Request.name.in_(names)
        )
    )
    if ids:
        session.execute(
            delete(
                models.Request
            ).where(
                models.Request.id.in_(ids)
            )
        )
    session.commit()


def _add_test_replicas_and_request(request_configs, scope, account, session):
    """
    Generate replicas and associated requests; one for each config in request_configs.
    """
    names = []
    requests = []
    for config in request_configs:
        name = generate_uuid()
        request = {
            'source_rse_id': '',
            'dest_rse_id': '',
            'request_type': RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name,
            'bytes': 1,
            'scope': scope,
            'retry_count': 1,
            'rule_id': generate_uuid(),
            'requested_at': datetime.now(),
            'account': account,
            'attributes': {
                'activity': 'User Subscription',
                'bytes': 1,
                'md5': '',
                'adler32': '',
            },
        }
        request.update({k: w for k, w in config.items() if k != 'attributes'})
        if config.get('attributes'):
            request['attributes'].update({k: w for k, w in config['attributes'].items()})

        names.append(name)
        requests.append(request)

        add_replica(request['source_rse_id'], request['scope'], request['name'], request['bytes'], account, session=session)

    queue_requests(requests, session=session)
    session.commit()
    return names


@pytest.mark.noparallel(reason='uses preparer and throttler')
@pytest.mark.usefixtures("core_config_mock", "file_config_mock")
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('conveyor', 'use_preparer', 'true')
]}], indirect=True)
class TestSimpleLimits:
    """
    Test the behavior of throttler on simple cases without overlapping limits.
    """

    user_activity = 'User Subscription'
    user_activity2 = 'User Subscription2'
    all_activities = 'all_activities'

    def _add_replicas_and_request(self, source_rse_id, dest_rse_id, scope, account, session):
        return _add_test_replicas_and_request(
            scope=scope, account=account, session=session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2021),  # requested after the request below but small enough for max_volume check
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'bytes': 3000},
                },
            ]
        )

    def test_dest_all_act_grouped_fifo_all(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release all waiting requests (DEST - ALL ACT - GFIFO). """
        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # no threshold when releasing -> release all waiting requests
        set_rse_transfer_limits(dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='grouped_fifo', session=db_session)

        name1, name2, name3, name4 = self._add_replicas_and_request(source_rse_id, dest_rse_id, scope=mock_scope, account=root_account, session=db_session)
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name2, 'scope': mock_scope}], root_account, session=db_session)

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()

        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request_1['state'] == RequestState.WAITING
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request_2['state'] == RequestState.WAITING
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id)
        assert request_4['state'] == RequestState.WAITING

        db_session.execute(
            delete(
                models.RSETransferLimit
            ).where(
                models.RSETransferLimit.rse_id.in_([source_rse_id, dest_rse_id])
            )
        )
        db_session.commit()

        throttler.run_once(logger=print, session=db_session)
        db_session.commit()

        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request_1['state'] == RequestState.QUEUED
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request_2['state'] == RequestState.QUEUED
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id)
        assert request_3['state'] == RequestState.QUEUED
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id)
        assert request_4['state'] == RequestState.QUEUED

    def test_dest_all_act_grouped_fifo_nothing(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release nothing (DEST - ALL ACT - GFIFO). """
        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # four waiting requests and one active requests but threshold is 1
        # more than 80% of the transfer limit are already used -> release nothing
        set_rse_transfer_limits(dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='grouped_fifo', session=db_session)
        request = models.Request(dest_rse_id=dest_rse_id, bytes=2, activity=self.user_activity, state=RequestState.SUBMITTED)
        request.save(session=db_session)
        name1, name2, name3, name4 = self._add_replicas_and_request(source_rse_id, dest_rse_id, scope=mock_scope, account=root_account, session=db_session)
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name2, 'scope': mock_scope}], root_account, session=db_session)

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request_1['state'] == RequestState.WAITING
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request_2['state'] == RequestState.WAITING
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id)
        assert request_4['state'] == RequestState.WAITING

    @skiplimitedsql
    def test_dest_all_act_grouped_fifo_subset(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ALL ACT - GFIFO). """
        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=10, max_transfers=1, deadline=1, strategy='grouped_fifo', session=db_session)
        name1, name2, name3, name4 = self._add_replicas_and_request(source_rse_id, dest_rse_id, scope=mock_scope, account=root_account, session=db_session)
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name2, 'scope': mock_scope}], root_account, session=db_session)

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        # released because it got requested first
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request_2['state'] == RequestState.QUEUED
        # released because of available volume
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id)
        assert request_3['state'] == RequestState.QUEUED
        # still waiting because there is no free volume
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id)
        assert request_4['state'] == RequestState.WAITING
        # deadline check should not work for destination RSEs - only for reading

    def test_dest_per_act_fifo_release_all(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release all waiting requests (DEST - ACT - FIFO). """
        if db_session.bind.dialect.name == 'mysql':
            return True

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # all activities limit applies to each activity -> release only one transfer
        set_rse_transfer_limits(dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='fifo', session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request2['state'] == RequestState.WAITING

        # active transfers + waiting requests are less than the threshold -> release all waiting requests
        _delete_requests(mock_scope, [name1, name2], session=db_session)
        set_rse_transfer_limits(dest_rse_id, activity=self.user_activity, max_transfers=3, strategy='fifo', session=db_session)
        set_rse_transfer_limits(dest_rse_id, max_transfers=3, activity=self.all_activities, strategy='fifo', session=db_session)
        request = models.Request(dest_rse_id=dest_rse_id, activity=self.user_activity, state=RequestState.SUBMITTED)
        request.save(session=db_session)
        name1, = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED

    def test_dest_per_act_fifo_release_nothing(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release nothing (DEST - ACT - FIFO). """
        if db_session.bind.dialect.name == 'mysql':
            return True

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # two waiting requests and one active requests but threshold is 1
        # more than 80% of the transfer limit are already used -> release nothing
        set_rse_transfer_limits(dest_rse_id, max_transfers=1, activity=self.user_activity, strategy='fifo', session=db_session)
        request = models.Request(dest_rse_id=dest_rse_id, bytes=2, activity=self.user_activity, state=RequestState.SUBMITTED)
        request.save(session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.WAITING
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request2['state'] == RequestState.WAITING

    def test_dest_per_act_fifo_release_subset(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ACT - FIFO). """
        if db_session.bind.dialect.name == 'mysql':
            return True

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # two waiting requests and no active requests but threshold is 1 -> release only 1 request
        set_rse_transfer_limits(dest_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo', session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        db_session.commit()
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request2['state'] == RequestState.WAITING

    def test_source_per_act_fifo_release_subset(self, rse_factory, mock_scope, vo, root_account, db_session):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ACT - FIFO). """

        if db_session.bind.dialect.name == 'mysql':
            return True

        _, source_rse_id = rse_factory.make_mock_rse()
        _, dest_rse_id = rse_factory.make_mock_rse()
        _, dest_rse_id2 = rse_factory.make_mock_rse()
        _, dest_rse_id3 = rse_factory.make_mock_rse()
        for rse_id in (dest_rse_id, dest_rse_id2, dest_rse_id3):
            add_distance(source_rse_id, rse_id, ranking=10)
        # two waiting requests and no active requests but threshold is 1 for one activity
        # one waiting request and no active requests but threshold is 0 for other activity -> release only 1 request for one activity
        set_rse_transfer_limits(source_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo', direction='source')
        set_rse_transfer_limits(source_rse_id, activity=self.user_activity2, max_transfers=0, strategy='fifo', direction='source')
        name1, name2, name3 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2018),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id3,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity2},
                },
            ]
        )

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id2)
        assert request2['state'] == RequestState.WAITING
        request3 = get_request_by_did(mock_scope, name3, dest_rse_id3)
        assert request3['state'] == RequestState.WAITING

    def test_source_all_act_fifo_release_subset(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ALL ACT - FIFO). """
        if db_session.bind.dialect.name == 'mysql':
            return True

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # two waiting requests and no active requests but threshold is 1 -> release only 1 request
        set_rse_transfer_limits(source_rse_id, activity=self.all_activities, max_transfers=1, strategy='fifo', direction='source', session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request2['state'] == RequestState.WAITING

    def test_dest_all_act_fifo_release_subset(self, rse_factory, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ALL ACT - FIFO). """
        if db_session.bind.dialect.name == 'mysql':
            return True

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        _, source_rse_id2 = rse_factory.make_mock_rse()
        _, dest_rse_id2 = rse_factory.make_mock_rse()
        add_distance(source_rse_id, dest_rse_id2, ranking=10)
        add_distance(source_rse_id2, dest_rse_id, ranking=10)
        add_distance(source_rse_id2, dest_rse_id2, ranking=10)

        # two waiting requests and no active requests but threshold 1 for one dest RSE
        # one waiting request and no active requests but threshold 0 for another dest RSE -> release only 1 request on one dest RSE
        set_rse_transfer_limits(dest_rse_id, activity=self.all_activities, max_transfers=1, strategy='fifo', session=db_session)
        set_rse_transfer_limits(dest_rse_id2, activity=self.all_activities, max_transfers=0, strategy='fifo', session=db_session)
        name1, name2, name3 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2018),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': source_rse_id2,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity2},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity2},
                },
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        # release because max_transfers=1
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        # waiting because limit already exceeded
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request2['state'] == RequestState.WAITING
        request3 = get_request_by_did(mock_scope, name3, dest_rse_id2)
        assert request3['state'] == RequestState.WAITING

    @skiplimitedsql
    def test_source_all_act_grouped_fifo_subset(self, rse_factory, mock_scope, db_session, root_account, connected_rse_pair):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ALL ACT - GFIFO). """
        if db_session.bind.dialect.name == 'mysql':
            return True

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        _, dest_rse_id2 = rse_factory.make_mock_rse()
        add_distance(source_rse_id, dest_rse_id2, ranking=10)

        set_rse_transfer_limits(source_rse_id, self.all_activities, volume=10, max_transfers=1, deadline=0, direction='source', strategy='grouped_fifo', session=db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.all_activities},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2021),
                    'attributes': {'activity': self.all_activities},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.all_activities},
                },
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name2, 'scope': mock_scope}], root_account, session=db_session)

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request_1['state'] == RequestState.WAITING
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id2, session=db_session)
        assert request_2['state'] == RequestState.WAITING
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id2, session=db_session)
        assert request_4['state'] == RequestState.WAITING

        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        # released because it got requested first
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id2)
        assert request_2['state'] == RequestState.QUEUED
        # still waiting, volume check is only working for destination RSEs (writing)
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id2)
        assert request_4['state'] == RequestState.WAITING


@pytest.mark.noparallel(reason='uses preparer and throttler')
@pytest.mark.usefixtures("core_config_mock", "file_config_mock")
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('conveyor', 'use_preparer', 'true')
]}], indirect=True)
class TestOverlappingLimits:
    user_activity = 'User Subscription'
    user_activity2 = 'User Subscription2'
    user_activity3 = 'User Subscription3'
    all_activities = 'all_activities'

    def test_source_dest_mixed_act(self, rse_factory, mock_scope, vo, root_account, db_session):
        """
        """

        if db_session.bind.dialect.name == 'mysql':
            return True

        _, source_rse_id = rse_factory.make_mock_rse()
        _, dest_rse_id = rse_factory.make_mock_rse()
        _, dest_rse_id2 = rse_factory.make_mock_rse()
        _, dest_rse_id3 = rse_factory.make_mock_rse()
        for rse_id in (dest_rse_id, dest_rse_id2, dest_rse_id3):
            add_distance(source_rse_id, rse_id, ranking=10)
        # two waiting requests and no active requests but threshold is 1 for one activity
        # one waiting request and no active requests but threshold is 0 for other activity -> release only 1 request for one activity
        set_rse_transfer_limits(source_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo', direction='source')
        set_rse_transfer_limits(source_rse_id, activity=self.all_activities, max_transfers=3, strategy='fifo', direction='source')
        set_rse_transfer_limits(dest_rse_id, activity=self.user_activity2, max_transfers=1, strategy='fifo', direction='destination')
        set_rse_transfer_limits(dest_rse_id, activity=self.all_activities, max_transfers=4, strategy='fifo', direction='destination')
        name1, name2, name3, name4, name5 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2018),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2019),
                    'attributes': {'activity': self.user_activity2},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity2},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity3},
                }
            ]
        )

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        throttler.run_once(logger=print, session=db_session)
        db_session.commit()
        request = get_request_by_did(mock_scope, name1, dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id)
        assert request2['state'] == RequestState.WAITING
        request3 = get_request_by_did(mock_scope, name3, dest_rse_id)
        assert request3['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name4, dest_rse_id)
        assert request['state'] == RequestState.WAITING
        request2 = get_request_by_did(mock_scope, name5, dest_rse_id)
        assert request2['state'] == RequestState.QUEUED


@pytest.mark.noparallel(reason='uses preparer and throttler')
@pytest.mark.usefixtures("core_config_mock", "file_config_mock")
@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('conveyor', 'use_preparer', 'true')
]}], indirect=True)
class TestRequestCoreRelease:
    """Test release methods used in throttler."""
    user_activity = 'User Subscription'
    user_activity2 = 'User Subscription2'
    all_activities = 'all_activities'

    @skiplimitedsql
    def test_release_waiting_requests_per_free_volume(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ REQUEST (CORE): release waiting requests that fit grouped in available volume."""
        # release unattached requests that fit in available volume with respect to already submitted transfers

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        dummy_request = models.Request(dest_rse_id=dest_rse_id, bytes=2, activity=self.all_activities, state=RequestState.SUBMITTED)
        dummy_request.save(session=db_session)
        volume = 10
        set_rse_transfer_limits(dest_rse_id, self.user_activity, max_transfers=1, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=db_session)
        name1, name2, name3 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2015),
                    'attributes': {'bytes': 8},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'bytes': 2},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                    'attributes': {'bytes': 10},
                },
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_per_free_volume(dest_rse_id, volume=volume, session=db_session)
        # released because small enough
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        # still waiting because requested later and to big
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING
        # still waiting because too big
        request = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING

        # release attached requests that fit together with the dataset in available volume with respect to already submitted transfers
        _delete_requests(mock_scope, [name1, name2, name3], ids=[dummy_request['id']], session=db_session)
        dummy_request = models.Request(dest_rse_id=dest_rse_id, bytes=2, activity=self.all_activities, state=RequestState.SUBMITTED)
        dummy_request.save(session=db_session)
        volume = 10
        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2015),
                    'attributes': {'bytes': 6},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'bytes': 2},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                    'attributes': {'bytes': 10},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2030),
                    'attributes': {'bytes': 2},
                },
            ]
        )
        dataset1_name = generate_uuid()
        add_did(mock_scope, dataset1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset1_name, [{'name': name1, 'scope': mock_scope}, {'name': name4, 'scope': mock_scope}], root_account, session=db_session)
        dataset2_name = generate_uuid()
        add_did(mock_scope, dataset2_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset2_name, [{'name': name2, 'scope': mock_scope}, {'name': name3, 'scope': mock_scope}], root_account, session=db_session)
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_per_free_volume(dest_rse_id, volume=volume, session=db_session)
        # released because dataset fits in volume
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name4, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        # waiting because dataset is too big
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING
        request = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING

        # release requests with no available volume -> release nothing
        _delete_requests(mock_scope, [name1, name2, name3, name4], ids=[dummy_request['id']], session=db_session)
        volume = 0
        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=db_session)
        name1, = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_per_free_volume(dest_rse_id, volume=volume, session=db_session)
        # waiting because no available volume
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING

    @skiplimitedsql
    def test_release_waiting_requests_grouped_fifo(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ REQUEST (CORE): release waiting requests based on grouped FIFO. """

        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # set volume and deadline to 0 to check first without releasing extra requests
        set_rse_transfer_limits(dest_rse_id, self.user_activity, max_transfers=1, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=0, max_transfers=1, session=db_session)

        # one request with an unattached DID -> one request should be released
        name, = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
            ]
        )

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_grouped_fifo(dest_rse_id, count=1, volume=0, deadline=0, session=db_session)
        request = get_request_by_did(mock_scope, name, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED

        # one request with an attached DID -> one request should be released
        _delete_requests(mock_scope, [name], session=db_session)
        name, = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
            ]
        )
        dataset_name = generate_uuid()
        add_did(mock_scope, dataset_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_name, [{'name': name, 'scope': mock_scope}], root_account, session=db_session)
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_grouped_fifo(dest_rse_id, count=1, volume=0, deadline=0, session=db_session)
        request = get_request_by_did(mock_scope, name, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED

        # five requests with different requested_at and multiple attachments per collection -> release only one request -> two requests of one collection should be released
        _delete_requests(mock_scope, [name], session=db_session)
        name1, name2, name3, name4, name5 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2000)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2010)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        dataset_2_name = generate_uuid()
        add_did(mock_scope, dataset_2_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}, {'name': name2, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_2_name, [{'name': name3, 'scope': mock_scope}, {'name': name4, 'scope': mock_scope}], root_account, session=db_session)

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_grouped_fifo(dest_rse_id, count=1, deadline=0, volume=0, session=db_session)
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request_1['state'] == RequestState.QUEUED
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request_2['state'] == RequestState.QUEUED
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id, session=db_session)
        assert request_4['state'] == RequestState.WAITING
        request_5 = get_request_by_did(mock_scope, name5, dest_rse_id, session=db_session)
        assert request_5['state'] == RequestState.WAITING

        # with maximal volume check -> release one request -> three requests should be released because of attachments and free volume space
        _delete_requests(mock_scope, [name1, name2, name3, name4, name5], session=db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2000)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
                # 2021: requested after the request below but small enough for max_volume check
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2021)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020), 'attributes': {'bytes': 3000}},
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name2, 'scope': mock_scope}], root_account, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=10, max_transfers=1, session=db_session)

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        amount_updated_requests = release_waiting_requests_grouped_fifo(dest_rse_id, count=1, deadline=0, volume=10, session=db_session)
        assert amount_updated_requests == 3
        # released because it got requested first
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request_2['state'] == RequestState.QUEUED
        # released because of available volume
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request_3['state'] == RequestState.QUEUED
        # still waiting because there is no free volume
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id, session=db_session)
        assert request_4['state'] == RequestState.WAITING

        # with maximal volume check -> release one request -> two requests should be released because of attachments
        _delete_requests(mock_scope, [name1, name2, name3, name4], session=db_session)
        request = models.Request(dest_rse_id=dest_rse_id, bytes=2, activity=self.all_activities, state=RequestState.SUBMITTED)
        request.save(session=db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2000)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020), 'attributes': {'bytes': 2}},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(mock_scope, dataset_1_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name1, 'scope': mock_scope}], root_account, session=db_session)
        attach_dids(mock_scope, dataset_1_name, [{'name': name2, 'scope': mock_scope}], root_account, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, volume=5, max_transfers=1, session=db_session)
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_grouped_fifo(dest_rse_id, count=1, deadline=0, volume=5, session=db_session)
        # released because it got requested first
        request_1 = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request_2['state'] == RequestState.QUEUED
        # still waiting because there is no free volume after releasing the two requests above
        request_3 = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(mock_scope, name4, dest_rse_id, session=db_session)
        assert request_4['state'] == RequestState.WAITING

        # with deadline check -> release 0 requests -> 1 request should be released nonetheless
        _delete_requests(mock_scope, [name1, name2, name3, name4], session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now() - timedelta(hours=2)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now()},
            ]
        )

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_grouped_fifo(source_rse_id=source_rse_id, count=0, deadline=1, volume=0, session=db_session)
        # queued because of deadline
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        # waiting because count=0
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING

    def test_release_waiting_requests_fifo(self, mock_scope, jdoe_account, db_session, root_account, connected_rse_pair):
        """ REQUEST (CORE): release waiting requests based on FIFO. """
        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # without account and activity check
        # two requests -> release one request -> request with oldest requested_at date should be released
        set_rse_transfer_limits(dest_rse_id, self.user_activity, max_transfers=1, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, max_transfers=1, session=db_session)
        set_rse_transfer_limits(dest_rse_id, 'ignore', max_transfers=1, session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_fifo(dest_rse_id, count=1, session=db_session)
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request2['state'] == RequestState.WAITING

        # with activity and account check
        # two requests -> release two request -> requests with correct account and activity should be released
        _delete_requests(mock_scope, [name1, name2], session=db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2018),
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': 'ignore'},
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'account': jdoe_account,
                }, {
                    'source_rse_id': source_rse_id,
                    'dest_rse_id': dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),  # requested latest but account and activity are correct
                },
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_fifo(dest_rse_id, count=2, account=root_account, activity=self.user_activity, session=db_session)
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING
        request = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING
        request = get_request_by_did(mock_scope, name4, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED

    def test_release_waiting_requests_all(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ REQUEST (CORE): release all waiting requests. """
        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        set_rse_transfer_limits(dest_rse_id, self.user_activity, max_transfers=1, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, max_transfers=1, session=db_session)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_all_waiting_requests(dest_rse_id, session=db_session)
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED

    @skiplimitedsql
    def test_release_waiting_requests_per_deadline(self, mock_scope, db_session, root_account, connected_rse_pair):
        """ REQUEST (CORE): release grouped waiting requests that exceeded waiting time."""
        source_rse, source_rse_id, dest_rse, dest_rse_id = connected_rse_pair

        # a request that exceeded the maximal waiting time to be released (1 hour) -> release one request -> only the exceeded request should be released
        set_rse_transfer_limits(dest_rse_id, self.user_activity, max_transfers=1, session=db_session)
        set_rse_transfer_limits(dest_rse_id, self.all_activities, max_transfers=1, session=db_session)
        two_hours = timedelta(hours=2)
        name1, name2 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now() - two_hours},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now()},
            ]
        )
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_per_deadline(source_rse_id=source_rse_id, deadline=1, session=db_session)
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING

        # a request that exceeded the maximal waiting time to be released (1 hour) -> release one request -> release all requests of the same dataset
        name1, name2, name3 = _add_test_replicas_and_request(
            scope=mock_scope, account=root_account, session=db_session,
            request_configs=[
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now() - two_hours},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now()},
                {'source_rse_id': source_rse_id, 'dest_rse_id': dest_rse_id, 'requested_at': datetime.now()},
            ]
        )
        dataset_name = generate_uuid()
        add_did(mock_scope, dataset_name, DIDType.DATASET, root_account, session=db_session)
        attach_dids(mock_scope, dataset_name, [{'name': name1, 'scope': mock_scope}, {'name': name2, 'scope': mock_scope}], root_account, session=db_session)
        preparer.run_once(session=db_session, logger=print)
        db_session.commit()
        release_waiting_requests_per_deadline(source_rse_id=source_rse_id, deadline=1, session=db_session)
        request = get_request_by_did(mock_scope, name1, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(mock_scope, name3, dest_rse_id, session=db_session)
        assert request['state'] == RequestState.WAITING
