# -*- coding: utf-8 -*-
# Copyright 2019-2021 CERN
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import unittest
from datetime import datetime, timedelta

import pytest

from rucio.common.config import config_get_bool, config_set, config_remove_option
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import attach_dids, add_did
from rucio.core.replica import add_replica
from rucio.core.request import queue_requests, get_request_by_did, release_waiting_requests_per_deadline, release_all_waiting_requests, release_waiting_requests_fifo, release_waiting_requests_grouped_fifo, release_waiting_requests_per_free_volume
from rucio.core.rse import get_rse_id, set_rse_transfer_limits
from rucio.daemons.conveyor import throttler, preparer
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import DIDType, RequestType, RequestState
from rucio.tests.common import skiplimitedsql
from rucio.tests.common_server import get_vo


def _add_test_replicas_and_request(request_configs, vo=None, scope=None, account=None, session=None):
    """
    Generate replicas and associated requests; one for each config in request_configs.
    """
    if vo is None:
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            vo = {'vo': get_vo()}
        else:
            vo = {}
    if scope is None:
        scope = InternalScope('mock', **vo)
    if account is None:
        account = InternalAccount('root', **vo)
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


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp, uses pre-defined rses, changes global configuration value')
@pytest.mark.usefixtures("core_config_mock")
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'DEST_PER_ALL_ACT')]
}], indirect=True)
class TestThrottlerGroupedFIFO(unittest.TestCase):
    """Throttler per destination RSE and on all activites per grouped FIFO
    """

    db_session = None

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'
        config_set('conveyor', 'use_preparer', 'true')

    def setUp(self):
        self.db_session = session.get_session()
        self.dialect = self.db_session.bind.dialect.name
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()
        self.db_session.close()

    @classmethod
    def tearDownClass(cls):
        config_remove_option('conveyor', 'use_preparer')

    def _add_replicas_and_request(self):
        return _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2021),  # requested after the request below but small enough for max_volume check
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'bytes': 3000},
                },
            ]
        )

    def test_preparer_throttler_grouped_fifo_all(self):
        """ THROTTLER (CLIENTS): throttler release all waiting requests (DEST - ALL ACT - GFIFO). """

        # no threshold when releasing -> release all waiting requests
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='grouped_fifo', session=self.db_session)

        name1, name2, name3, name4 = self._add_replicas_and_request()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()

        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request_1['state'] == RequestState.WAITING
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request_2['state'] == RequestState.WAITING
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert request_4['state'] == RequestState.WAITING

        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()

        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()

        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request_1['state'] == RequestState.QUEUED
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request_2['state'] == RequestState.QUEUED
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert request_3['state'] == RequestState.QUEUED
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert request_4['state'] == RequestState.QUEUED

    def test_throttler_grouped_fifo_nothing(self):
        """ THROTTLER (CLIENTS): throttler release nothing (DEST - ALL ACT - GFIFO). """

        # four waiting requests and one active requests but threshold is 1
        # more than 80% of the transfer limit are already used -> release nothing
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='grouped_fifo', session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.user_activity, state=RequestState.SUBMITTED)
        request.save(session=self.db_session)
        name1, name2, name3, name4 = self._add_replicas_and_request()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request_1['state'] == RequestState.WAITING
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request_2['state'] == RequestState.WAITING
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert request_4['state'] == RequestState.WAITING

    @skiplimitedsql
    def test_throttler_grouped_fifo_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ALL ACT - GFIFO). """
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=10, max_transfers=1, deadline=1, strategy='grouped_fifo', session=self.db_session)
        name1, name2, name3, name4 = self._add_replicas_and_request()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request_2['state'] == RequestState.QUEUED
        # released because of available volume
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert request_3['state'] == RequestState.QUEUED
        # still waiting because there is no free volume
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert request_4['state'] == RequestState.WAITING
        # deadline check should not work for destination RSEs - only for reading


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp, uses pre-defined rses, changes global configuration value')
@pytest.mark.usefixtures("core_config_mock")
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'DEST_PER_ACT')]
}], indirect=True)
class TestThrottlerFIFO(unittest.TestCase):
    """Throttler per destination RSE and on each activites per FIFO
    """
    db_session = None

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'
        config_set('conveyor', 'use_preparer', 'true')

    def setUp(self):
        self.db_session = session.get_session()
        self.dialect = self.db_session.bind.dialect.name
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()
        self.db_session.close()

    @classmethod
    def tearDownClass(cls):
        config_remove_option('conveyor', 'use_preparer')

    def test_throttler_fifo_release_all(self):
        """ THROTTLER (CLIENTS): throttler release all waiting requests (DEST - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True
        # no threshold -> release all waiting requests
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='fifo', session=self.db_session)
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request2['state'] == RequestState.QUEUED

        # active transfers + waiting requests are less than the threshold -> release all waiting requests
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        set_rse_transfer_limits(self.dest_rse_id, activity=self.user_activity, max_transfers=3, strategy='fifo', session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, activity=self.user_activity, state=RequestState.SUBMITTED)
        request.save(session=self.db_session)
        name1, = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request['state'] == RequestState.QUEUED

    def test_throttler_fifo_release_nothing(self):
        """ THROTTLER (CLIENTS): throttler release nothing (DEST - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and one active requests but threshold is 1
        # more than 80% of the transfer limit are already used -> release nothing
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.user_activity, strategy='fifo', session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.user_activity, state=RequestState.SUBMITTED)
        request.save(session=self.db_session)
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request['state'] == RequestState.WAITING
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request2['state'] == RequestState.WAITING

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold is 1 -> release only 1 request
        set_rse_transfer_limits(self.dest_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo', session=self.db_session)
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        self.db_session.commit()
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request2['state'] == RequestState.WAITING


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp')
@pytest.mark.usefixtures("core_config_mock", 'file_config_mock')
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'SRC_PER_ACT')]
}], indirect=True)
@pytest.mark.parametrize("file_config_mock", [{
    "overrides": [('conveyor', 'use_preparer', 'true')]
}], indirect=True)
class TestThrottlerFIFOSRCACT:
    """Throttler per source RSE and on each activites per FIFO."""

    user_activity = 'User Subscription'
    user_activity2 = 'User Subscription2'
    all_activities = 'all_activities'

    def test_throttler_fifo_release_subset(self, rse_factory, mock_scope, vo, root_account, db_session):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ACT - FIFO). """

        if db_session.bind.dialect.name == 'mysql':
            return True

        db_session.query(models.Request).delete()
        db_session.commit()

        _, source_rse_id = rse_factory.make_mock_rse()
        _, dest_rse_id = rse_factory.make_mock_rse()
        _, dest_rse_id2 = rse_factory.make_mock_rse()
        _, dest_rse_id3 = rse_factory.make_mock_rse()
        # two waiting requests and no active requests but threshold is 1 for one activity
        # one waiting request and no active requests but threshold is 0 for other activity -> release only 1 request for one activity
        set_rse_transfer_limits(source_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo')
        set_rse_transfer_limits(source_rse_id, activity=self.user_activity2, max_transfers=0, strategy='fifo')
        name1, name2, name3 = _add_test_replicas_and_request(
            vo={'vo': vo}, scope=mock_scope, account=root_account, session=db_session,
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


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp, uses pre-defined rses, changes global configuration value')
@pytest.mark.usefixtures("core_config_mock")
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'SRC_PER_ALL_ACT')]
}], indirect=True)
class TestThrottlerFIFOSRCALLACT(unittest.TestCase):
    """Throttler per source RSE and on all activites per FIFO."""

    db_session = None

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'
        config_set('conveyor', 'use_preparer', 'true')

    def setUp(self):
        self.db_session = session.get_session()
        self.dialect = self.db_session.bind.dialect.name
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()
        self.db_session.close()

    @classmethod
    def tearDownClass(cls):
        config_remove_option('conveyor', 'use_preparer')

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ALL ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold is 1 -> release only 1 request
        set_rse_transfer_limits(self.source_rse_id, activity=self.all_activities, max_transfers=1, strategy='fifo', session=self.db_session)
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request2['state'] == RequestState.WAITING


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp, uses pre-defined rses, changes global configuration value')
@pytest.mark.usefixtures("core_config_mock")
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'DEST_PER_ALL_ACT')]
}], indirect=True)
class TestThrottlerFIFODESTALLACT(unittest.TestCase):
    """Throttler per destination RSE and on all activites per FIFO."""

    db_session = None

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.dest_rse = 'MOCK'
        cls.dest_rse2 = 'MOCK5'
        cls.source_rse = 'MOCK4'
        cls.source_rse2 = 'MOCK3'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.dest_rse_id2 = get_rse_id(cls.dest_rse2, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalScope('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.user_activity2 = 'User Subscription2'
        cls.all_activities = 'all_activities'
        config_set('conveyor', 'use_preparer', 'true')

    def setUp(self):
        self.db_session = session.get_session()
        self.dialect = self.db_session.bind.dialect.name
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()
        self.db_session.close()

    @classmethod
    def tearDownClass(cls):
        config_remove_option('conveyor', 'use_preparer')

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ALL ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold 1 for one dest RSE
        # one waiting request and no active requests but threshold 0 for another dest RSE -> release only 1 request on one dest RSE
        set_rse_transfer_limits(self.dest_rse_id, activity=self.all_activities, max_transfers=1, strategy='fifo', session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id2, activity=self.all_activities, max_transfers=0, strategy='fifo', session=self.db_session)
        name1, name2, name3 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2018),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': self.source_rse_id2,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity2},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.user_activity2},
                },
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        # release because max_transfers=1
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request['state'] == RequestState.QUEUED
        # waiting because limit already exceeded
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert request2['state'] == RequestState.WAITING
        request3 = get_request_by_did(self.scope, name3, self.dest_rse_id2)
        assert request3['state'] == RequestState.WAITING


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp, uses pre-defined rses, changes global configuration value')
@pytest.mark.usefixtures("core_config_mock")
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'SRC_PER_ALL_ACT')]
}], indirect=True)
class TestThrottlerGroupedFIFOSRCALLACT(unittest.TestCase):
    """Throttler per source RSE and on all activites per grouped FIFO."""

    db_session = None

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_2 = 'MOCK3'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.dest_rse_id_2 = get_rse_id(cls.dest_rse_2, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'
        config_set('conveyor', 'use_preparer', 'true')

    def setUp(self):
        self.db_session = session.get_session()
        self.dialect = self.db_session.bind.dialect.name
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()
        self.db_session.close()

    @classmethod
    def tearDownClass(cls):
        config_remove_option('conveyor', 'use_preparer')

    @skiplimitedsql
    def test_preparer_throttler_grouped_fifo_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ALL ACT - GFIFO). """
        if self.dialect == 'mysql':
            return True

        set_rse_transfer_limits(self.source_rse_id, self.all_activities, volume=10, max_transfers=1, deadline=0, strategy='grouped_fifo', session=self.db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                    'attributes': {'activity': self.user_activity},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id_2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.all_activities},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2021),
                    'attributes': {'activity': self.all_activities},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id_2,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': self.all_activities},
                },
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request_1['state'] == RequestState.WAITING
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id_2, session=self.db_session)
        assert request_2['state'] == RequestState.WAITING
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id_2, session=self.db_session)
        assert request_4['state'] == RequestState.WAITING

        throttler.run_once(logger=print, session=self.db_session)
        self.db_session.commit()
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id_2)
        assert request_2['state'] == RequestState.QUEUED
        # still waiting, volume check is only working for destination RSEs (writing)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id_2)
        assert request_4['state'] == RequestState.WAITING


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp, uses pre-defined rses, changes global configuration value')
@pytest.mark.usefixtures("core_config_mock")
@pytest.mark.parametrize("core_config_mock", [{
    "table_content": [('throttler', 'mode', 'DEST_PER_ACT')]
}], indirect=True)
class TestRequestCoreRelease(unittest.TestCase):
    """Test release methods used in throttler."""

    db_session = None

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.source_rse2 = 'MOCK5'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'
        config_set('conveyor', 'use_preparer', 'true')

    def setUp(self):
        self.db_session = session.get_session()
        self.dialect = self.db_session.bind.dialect.name
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Distance).delete()
        # set transfer limits to put requests in waiting state
        set_rse_transfer_limits(self.dest_rse_id, self.user_activity, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, 'ignore', max_transfers=1, session=self.db_session)
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        config_remove_option('conveyor', 'use_preparer')

    @skiplimitedsql
    def test_release_waiting_requests_per_free_volume(self):
        """ REQUEST (CORE): release waiting requests that fit grouped in available volume."""
        # release unattached requests that fit in available volume with respect to already submitted transfers
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.all_activities, state=RequestState.SUBMITTED)
        request.save(session=self.db_session)
        volume = 10
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=self.db_session)
        name1, name2, name3 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2015),
                    'attributes': {'bytes': 8},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'bytes': 2},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                    'attributes': {'bytes': 10},
                },
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # released because small enough
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        # still waiting because requested later and to big
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING
        # still waiting because too big
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING

        # release attached requests that fit together with the dataset in available volume with respect to already submitted transfers
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.all_activities, state=RequestState.SUBMITTED)
        request.save(session=self.db_session)
        volume = 10
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=self.db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2015),
                    'attributes': {'bytes': 6},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'bytes': 2},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2000),
                    'attributes': {'bytes': 10},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2030),
                    'attributes': {'bytes': 2},
                },
            ]
        )
        dataset1_name = generate_uuid()
        add_did(self.scope, dataset1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset1_name, [{'name': name1, 'scope': self.scope}, {'name': name4, 'scope': self.scope}], self.account, session=self.db_session)
        dataset2_name = generate_uuid()
        add_did(self.scope, dataset2_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset2_name, [{'name': name2, 'scope': self.scope}, {'name': name3, 'scope': self.scope}], self.account, session=self.db_session)
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # released because dataset fits in volume
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        # waiting because dataset is too big
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING

        # release requests with no available volume -> release nothing
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        volume = 0
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=self.db_session)
        name1, = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # waiting because no available volume
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING

    @skiplimitedsql
    def test_release_waiting_requests_grouped_fifo(self):
        """ REQUEST (CORE): release waiting requests based on grouped FIFO. """
        # set volume and deadline to 0 to check first without releasing extra requests
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=0, max_transfers=1, session=self.db_session)

        # one request with an unattached DID -> one request should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name, = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
            ]
        )

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, volume=0, deadline=0, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED

        # one request with an attached DID -> one request should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name, = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
            ]
        )
        dataset_name = generate_uuid()
        add_did(self.scope, dataset_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_name, [{'name': name, 'scope': self.scope}], self.account, session=self.db_session)
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, volume=0, deadline=0, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED

        # five requests with different requested_at and multiple attachments per collection -> release only one request -> two requests of one collection should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1, name2, name3, name4, name5 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2000)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2015)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2010)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        dataset_2_name = generate_uuid()
        add_did(self.scope, dataset_2_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}, {'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_2_name, [{'name': name3, 'scope': self.scope}, {'name': name4, 'scope': self.scope}], self.account, session=self.db_session)

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, deadline=0, volume=0, session=self.db_session)
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request_1['state'] == RequestState.QUEUED
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request_2['state'] == RequestState.QUEUED
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert request_4['state'] == RequestState.WAITING
        request_5 = get_request_by_did(self.scope, name5, self.dest_rse_id, session=self.db_session)
        assert request_5['state'] == RequestState.WAITING

        # with maximal volume check -> release one request -> three requests should be released because of attachments and free volume space
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2000)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
                # 2021: requested after the request below but small enough for max_volume check
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2021)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020), 'attributes': {'bytes': 3000}},
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=10, max_transfers=1, session=self.db_session)

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        amount_updated_requests = release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, deadline=0, volume=10, session=self.db_session)
        assert amount_updated_requests == 3
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request_2['state'] == RequestState.QUEUED
        # released because of available volume
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request_3['state'] == RequestState.QUEUED
        # still waiting because there is no free volume
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert request_4['state'] == RequestState.WAITING

        # with maximal volume check -> release one request -> two requests should be released because of attachments
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.all_activities, state=RequestState.SUBMITTED)
        request.save(session=self.db_session)
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2000)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020), 'attributes': {'bytes': 2}},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=5, max_transfers=1, session=self.db_session)
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, deadline=0, volume=5, session=self.db_session)
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request_1['state'] == RequestState.QUEUED
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request_2['state'] == RequestState.QUEUED
        # still waiting because there is no free volume after releasing the two requests above
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request_3['state'] == RequestState.WAITING
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert request_4['state'] == RequestState.WAITING

        # with deadline check -> release 0 requests -> 1 request should be released nonetheless
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now() - timedelta(hours=2)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now()},
            ]
        )

        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_grouped_fifo(self.source_rse_id, count=0, deadline=1, volume=0, session=self.db_session)
        # queued because of deadline
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        # waiting because count=0
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING

    def test_release_waiting_requests_fifo(self):
        """ REQUEST (CORE): release waiting requests based on FIFO. """
        # without account and activity check
        # two requests -> release one request -> request with oldest requested_at date should be released
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_fifo(self.dest_rse_id, count=1, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request2['state'] == RequestState.WAITING

        # with activity and account check
        # two requests -> release two request -> requests with correct account and activity should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1, name2, name3, name4 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2018),
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'attributes': {'activity': 'ignore'},
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),
                    'account': InternalAccount('jdoe', **self.vo),
                }, {
                    'source_rse_id': self.source_rse_id,
                    'dest_rse_id': self.dest_rse_id,
                    'requested_at': datetime.now().replace(year=2020),  # requested latest but account and activity are correct
                },
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_fifo(self.dest_rse_id, count=2, account=self.account, activity=self.user_activity, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING
        request = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED

    def test_release_waiting_requests_all(self):
        """ REQUEST (CORE): release all waiting requests. """
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2018)},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now().replace(year=2020)},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_all_waiting_requests(self.dest_rse_id, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED

    @skiplimitedsql
    def test_release_waiting_requests_per_deadline(self):
        """ REQUEST (CORE): release grouped waiting requests that exceeded waiting time."""
        # a request that exceeded the maximal waiting time to be released (1 hour) -> release one request -> only the exceeded request should be released
        set_rse_transfer_limits(self.source_rse_id, activity=self.all_activities, strategy='grouped_fifo', session=self.db_session)
        two_hours = timedelta(hours=2)
        name1, name2 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now() - two_hours},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now()},
            ]
        )
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_per_deadline(self.source_rse_id, deadline=1, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING

        # a request that exceeded the maximal waiting time to be released (1 hour) -> release one request -> release all requests of the same dataset
        name1, name2, name3 = _add_test_replicas_and_request(
            vo=self.vo, scope=self.scope, account=self.account, session=self.db_session,
            request_configs=[
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now() - two_hours},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now()},
                {'source_rse_id': self.source_rse_id, 'dest_rse_id': self.dest_rse_id, 'requested_at': datetime.now()},
            ]
        )
        dataset_name = generate_uuid()
        add_did(self.scope, dataset_name, DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_name, [{'name': name1, 'scope': self.scope}, {'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        preparer.run_once(session=self.db_session, logger=print)
        self.db_session.commit()
        release_waiting_requests_per_deadline(self.source_rse_id, deadline=1, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.QUEUED
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert request['state'] == RequestState.WAITING
