# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
#
# PY3K COMPATIBLE

from datetime import datetime
from nose.tools import assert_equal

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.config import set
from rucio.core.did import attach_dids, add_did
from rucio.core.replica import add_replica
from rucio.core.request import queue_requests, get_request_by_did
from rucio.core.rse import get_rse_id, set_rse_transfer_limits
from rucio.daemons.conveyor import throttler
from rucio.db.sqla import session, models, constants


# Throttler per destination RSE and on all activites per grouped FIFO
class TestThrottlerGroupedFIFO(object):
    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Config).delete()
        set('throttler', 'mode', 'DEST_PER_ALL_ACT', session=self.db_session)
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.commit()
        cls.db_session.close()

    def test_throttler_grouped_fifo_all(self):
        """ THROTTLER (CLIENTS): throttler release all waiting requests (DEST - ALL ACT - GFIFO). """

        # no threshold when releasing -> release all waiting requests
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='grouped_fifo', session=self.db_session)

        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        name4 = generate_uuid()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'bytes': 1,
            'scope': self.scope,
            'retry_count': 1,
            'rule_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2000),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'bytes': 2,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'bytes': 3,
            'requested_at': datetime.now().replace(year=2021),  # requested after the request below but small enough for max_volume check
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name4,
            'bytes': 3000,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3000,
                'md5': '',
                'adler32': ''
            }
        }]

        queue_requests(requests, session=self.db_session)
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request_1['state'], constants.RequestState.WAITING)
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request_2['state'], constants.RequestState.WAITING)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert_equal(request_3['state'], constants.RequestState.WAITING)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert_equal(request_4['state'], constants.RequestState.WAITING)

        throttler.run(once=True, sleep_time=1)
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request_1['state'], constants.RequestState.QUEUED)
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request_2['state'], constants.RequestState.QUEUED)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert_equal(request_3['state'], constants.RequestState.QUEUED)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert_equal(request_4['state'], constants.RequestState.QUEUED)

    def test_throttler_grouped_fifo_nothing(self):
        """ THROTTLER (CLIENTS): throttler release nothing (DEST - ALL ACT - GFIFO). """

        # four waiting requests and one active requests but threshold is 1
        # more than 80% of the transfer limit are already used -> release nothing
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='grouped_fifo', session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.user_activity, state=constants.RequestState.SUBMITTED)
        request.save(session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        name4 = generate_uuid()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'bytes': 1,
            'scope': self.scope,
            'retry_count': 1,
            'rule_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2000),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'bytes': 2,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'bytes': 3,
            'requested_at': datetime.now().replace(year=2021),  # requested after the request below but small enough for max_volume check
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name4,
            'bytes': 3000,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3000,
                'md5': '',
                'adler32': ''
            }
        }]

        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request_1['state'], constants.RequestState.WAITING)
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request_2['state'], constants.RequestState.WAITING)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert_equal(request_3['state'], constants.RequestState.WAITING)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert_equal(request_4['state'], constants.RequestState.WAITING)

    def test_throttler_grouped_fifo_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ALL ACT - GFIFO). """
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=10, max_transfers=1, deadline=1, strategy='grouped_fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        name4 = generate_uuid()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'bytes': 1,
            'scope': self.scope,
            'retry_count': 1,
            'rule_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2000),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'bytes': 2,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'bytes': 3,
            'requested_at': datetime.now().replace(year=2021),  # requested after the request below but small enough for max_volume check
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name4,
            'bytes': 3000,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3000,
                'md5': '',
                'adler32': ''
            }
        }]

        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request_1['state'], constants.RequestState.QUEUED)
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request_2['state'], constants.RequestState.QUEUED)
        # released because of available volume
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert_equal(request_3['state'], constants.RequestState.QUEUED)
        # still waiting because there is no free volume
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id)
        assert_equal(request_4['state'], constants.RequestState.WAITING)
        # deadline check should not work for destination RSEs - only for reading


# Throttler per destination RSE and on each activites per FIFO
class TestThrottlerFIFO(object):
    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Config).delete()
        set('throttler', 'mode', 'DEST_PER_ACT', session=self.db_session)
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.commit()
        cls.db_session.close()

    def test_throttler_fifo_release_all(self):
        """ THROTTLER (CLIENTS): throttler release all waiting requests (DEST - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True
        # no threshold -> release all waiting requests
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.all_activities, strategy='fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name2,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request2['state'], constants.RequestState.QUEUED)

        # active transfers + waiting requests are less than the threshold -> release all waiting requests
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, activity=self.user_activity, max_transfers=3, strategy='fifo', session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, activity=self.user_activity, state=constants.RequestState.SUBMITTED)
        request.save(session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.QUEUED)

    def test_throttler_fifo_release_nothing(self):
        """ THROTTLER (CLIENTS): throttler release nothing (DEST - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and one active requests but threshold is 1
        # more than 80% of the transfer limit are already used -> release nothing
        set_rse_transfer_limits(self.dest_rse_id, max_transfers=1, activity=self.user_activity, strategy='fifo', session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.user_activity, state=constants.RequestState.SUBMITTED)
        request.save(session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name2,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.WAITING)
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request2['state'], constants.RequestState.WAITING)

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold is 1 -> release only 1 request
        set_rse_transfer_limits(self.dest_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name2,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request2['state'], constants.RequestState.WAITING)


# Throttler per source RSE and on each activites per FIFO
class TestThrottlerFIFOSRCACT(object):
    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
        cls.dest_rse = 'MOCK'
        cls.dest_rse2 = 'MOCK5'
        cls.dest_rse3 = 'MOCK3'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.dest_rse_id2 = get_rse_id(cls.dest_rse2, **cls.vo)
        cls.dest_rse_id3 = get_rse_id(cls.dest_rse3, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.user_activity2 = 'User Subscription2'
        cls.all_activities = 'all_activities'

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Config).delete()
        set('throttler', 'mode', 'SRC_PER_ACT', session=self.db_session)
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.commit()
        cls.db_session.close()

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold is 1 for one activity
        # one waiting request and no active requests but threshold is 0 for other activity -> release only 1 request for one activity
        set_rse_transfer_limits(self.source_rse_id, activity=self.user_activity, max_transfers=1, strategy='fifo', session=self.db_session)
        set_rse_transfer_limits(self.source_rse_id, activity=self.user_activity2, max_transfers=0, strategy='fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id2,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name2,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id3,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name3,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity2,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id2)
        assert_equal(request2['state'], constants.RequestState.WAITING)
        request3 = get_request_by_did(self.scope, name3, self.dest_rse_id3)
        assert_equal(request3['state'], constants.RequestState.WAITING)


# Throttler per source RSE and on all activites per FIFO
class TestThrottlerFIFOSRCALLACT(object):
    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Config).delete()
        set('throttler', 'mode', 'SRC_PER_ALL_ACT', session=self.db_session)
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.commit()
        cls.db_session.close()

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ALL ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold is 1 -> release only 1 request
        set_rse_transfer_limits(self.source_rse_id, activity=self.all_activities, max_transfers=1, strategy='fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name2,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request2['state'], constants.RequestState.WAITING)


# Throttler per destination RSE and on all activites per FIFO
class TestThrottlerFIFODESTALLACT(object):
    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
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

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Config).delete()
        set('throttler', 'mode', 'DEST_PER_ALL_ACT', session=self.db_session)
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.commit()
        cls.db_session.close()

    def test_throttler_fifo_release_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (DEST - ALL ACT - FIFO). """
        if self.dialect == 'mysql':
            return True

        # two waiting requests and no active requests but threshold 1 for one dest RSE
        # one waiting request and no active requests but threshold 0 for another dest RSE -> release only 1 request on one dest RSE
        set_rse_transfer_limits(self.dest_rse_id, activity=self.all_activities, max_transfers=1, strategy='fifo', session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id2, activity=self.all_activities, max_transfers=0, strategy='fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id2, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id2,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name2,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity2,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id2,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2020),
            'name': name3,
            'account': self.account,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity2,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)
        # release because max_transfers=1
        request = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        # waiting because limit already exceeded
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id)
        assert_equal(request2['state'], constants.RequestState.WAITING)
        request3 = get_request_by_did(self.scope, name3, self.dest_rse_id2)
        assert_equal(request3['state'], constants.RequestState.WAITING)


# Throttler per source RSE and on all activites per grouped FIFO
class TestThrottlerGroupedFIFOSRCALLACT(object):
    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
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

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Config).delete()
        set('throttler', 'mode', 'SRC_PER_ALL_ACT', session=self.db_session)
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.commit()
        cls.db_session.close()

    def test_throttler_grouped_fifo_subset(self):
        """ THROTTLER (CLIENTS): throttler release subset of waiting requests (SRC - ALL ACT - GFIFO). """
        if self.dialect == 'mysql':
            return True

        set_rse_transfer_limits(self.source_rse_id, self.all_activities, volume=10, max_transfers=1, deadline=0, strategy='grouped_fifo', session=self.db_session)
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        name4 = generate_uuid()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'bytes': 1,
            'scope': self.scope,
            'retry_count': 1,
            'rule_id': generate_uuid(),
            'requested_at': datetime.now().replace(year=2000),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id_2,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'bytes': 2,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.all_activities,
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'bytes': 3,
            'requested_at': datetime.now().replace(year=2021),  # requested after the request below but small enough for max_volume check
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.all_activities,
                'bytes': 3,
                'md5': '',
                'adler32': ''
            }
        }, {
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id_2,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name4,
            'bytes': 3000,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 3000,
                'md5': '',
                'adler32': ''
            }
        }]

        queue_requests(requests, session=self.db_session)
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request_1['state'], constants.RequestState.WAITING)
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id_2, session=self.db_session)
        assert_equal(request_2['state'], constants.RequestState.WAITING)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request_3['state'], constants.RequestState.WAITING)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id_2, session=self.db_session)
        assert_equal(request_4['state'], constants.RequestState.WAITING)

        self.db_session.commit()
        throttler.run(once=True, sleep_time=1)

        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id)
        assert_equal(request_1['state'], constants.RequestState.QUEUED)
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id_2)
        assert_equal(request_2['state'], constants.RequestState.QUEUED)
        # still waiting, volume check is only working for destination RSEs (writing)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id)
        assert_equal(request_3['state'], constants.RequestState.WAITING)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id_2)
        assert_equal(request_4['state'], constants.RequestState.WAITING)
