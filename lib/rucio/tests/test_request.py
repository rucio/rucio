# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
from paste.fixture import TestApp

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, parse_response
from rucio.core.config import set as config_set
from rucio.core.did import attach_dids, add_did
# from rucio.core.distance import add_distance
from rucio.core.replica import add_replica
from rucio.core.request import release_all_waiting_requests, queue_requests, get_request_by_did, release_waiting_requests_per_free_volume,\
    release_waiting_requests_grouped_fifo, release_waiting_requests_fifo, list_requests, release_waiting_requests_per_deadline
from rucio.core.rse import get_rse_id, set_rse_transfer_limits, add_rse_attribute
from rucio.db.sqla import session, models, constants
from rucio.web.rest.authentication import APP as auth_app
from rucio.web.rest.request import APP as request_app


class TestRequestCoreQueue(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
        cls.dest_rse = 'MOCK'
        cls.dest_rse2 = 'MOCK2'
        cls.source_rse = 'MOCK4'
        cls.source_rse2 = 'MOCK5'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.dest_rse_id2 = get_rse_id(cls.dest_rse2, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)
        cls.user_activity = 'User Subscription'

    def setUp(self):
        self.db_session.query(models.Source).delete()
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Distance).delete()
        self.db_session.query(models.Config).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()

    def test_queue_requests_state_no_throttler(self):
        """ REQUEST (CORE): queue requests with default throttler mode (None). """
        name = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id2, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)

        set_rse_transfer_limits(self.dest_rse_id, self.user_activity, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id2, self.user_activity, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.source_rse_id, self.user_activity, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.source_rse_id2, self.user_activity, max_transfers=1, session=self.db_session)

        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'src_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'src_rse_id': self.source_rse_id2,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': 'unknown',
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id2,
            'src_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name3, self.dest_rse_id2, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)

    # def test_queue_requests_source_rse(self):
    #     """ REQUEST (CORE): queue requests and select correct source RSE. """
    #     # test correct selection of source RSE
    #     name = generate_uuid()
    #     size = 8
    #     add_replica(self.source_rse_id, self.scope, name, size, self.account, session=self.db_session)
    #     add_replica(self.source_rse_id2, self.scope, name, size, self.account, session=self.db_session)
    #     add_distance(self.source_rse_id, self.dest_rse_id, 1, session=self.db_session)
    #     add_distance(self.source_rse_id2, self.dest_rse_id, 2, session=self.db_session)
    #     requests = [{
    #         'dest_rse_id': self.dest_rse_id,
    #         'request_type': constants.RequestType.TRANSFER,
    #         'request_id': generate_uuid(),
    #         'name': name,
    #         'scope': self.scope,
    #         'rule_id': generate_uuid(),
    #         'retry_count': 1,
    #         'requested_at': datetime.now().replace(year=2015),
    #         'attributes': {
    #             'activity': self.user_activity,
    #             'bytes': size,
    #             'md5': '',
    #             'adler32': ''
    #         }
    #     }]
    #     queue_requests(requests, session=self.db_session)
    #     request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
    #     # select source RSE with smallest distance
    #     assert_equal(request['source_rse_id'], self.source_rse_id)
    #     assert_equal(request['name'], name)
    #     assert_equal(request['scope'], self.scope)
    #     assert_equal(request['state'], constants.RequestState.QUEUED)

    def test_queue_requests_state_1(self):
        """ REQUEST (CORE): queue requests and set correct request state. """
        # test correct request state depending on throttler mode
        config_set('throttler', 'mode', 'DEST_PER_ACT', session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.user_activity, max_transfers=1, session=self.db_session)
        size = 1
        name = generate_uuid()
        add_replica(self.source_rse_id2, self.scope, name, size, self.account, session=self.db_session)
        name2 = generate_uuid()
        add_replica(self.source_rse_id2, self.scope, name2, size, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': self.user_activity,
                'bytes': size,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': 'Activity without limit',
                'bytes': size,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)

    def test_queue_requests_state_2(self):
        """ REQUEST (CORE): queue requests and set correct request state. """
        config_set('throttler', 'mode', 'SRC_PER_ACT', session=self.db_session)
        size = 1
        name = generate_uuid()
        add_replica(self.source_rse_id2, self.scope, name, size, self.account, session=self.db_session)
        name2 = generate_uuid()
        add_replica(self.source_rse_id2, self.scope, name2, size, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': self.user_activity,
                'bytes': size,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)


class TestRequestCoreRelease(object):

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
        cls.source_rse2 = 'MOCK5'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)
        cls.scope = InternalScope('mock', **cls.vo)
        cls.account = InternalAccount('root', **cls.vo)
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Distance).delete()
        self.db_session.query(models.Config).delete()
        # set transfer limits to put requests in waiting state
        set_rse_transfer_limits(self.dest_rse_id, self.user_activity, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, 'ignore', max_transfers=1, session=self.db_session)
        config_set('throttler', 'mode', 'DEST_PER_ACT', session=self.db_session)
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()

    def test_release_waiting_requests_per_free_volume(self):
        """ REQUEST (CORE): release waiting requests that fit grouped in available volume."""
        # release unattached requests that fit in available volume with respect to already submitted transfers
        name1 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        name3 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.all_activities, state=constants.RequestState.SUBMITTED)
        request.save(session=self.db_session)
        volume = 10
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': 'User Subscription',
                'bytes': 8,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'requested_at': datetime.now().replace(year=2020),
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': 'User Subscription',
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2000),
            'attributes': {
                'activity': 'User Subscription',
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # released because small enough
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        # still waiting because requested later and to big
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)
        # still waiting because too big
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)

        # release attached requests that fit together with the dataset in available volume with respect to already submitted transfers
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        name3 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        name4 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        dataset1_name = generate_uuid()
        add_did(self.scope, dataset1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset1_name, [{'name': name1, 'scope': self.scope}, {'name': name4, 'scope': self.scope}], self.account, session=self.db_session)
        dataset2_name = generate_uuid()
        add_did(self.scope, dataset2_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset2_name, [{'name': name2, 'scope': self.scope}, {'name': name3, 'scope': self.scope}], self.account, session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.all_activities, state=constants.RequestState.SUBMITTED)
        request.save(session=self.db_session)
        volume = 10
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 6,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name2,
            'requested_at': datetime.now().replace(year=2020),
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2000),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name4,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2030),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 2,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # released because dataset fits in volume
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        # waiting because dataset is too big
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)

        # release requests with no available volume -> release nothing
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        add_replica(self.dest_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        volume = 0
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=volume, max_transfers=1, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 8,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # waiting because no available volume
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)

    def test_release_waiting_requests_grouped_fifo(self):
        """ REQUEST (CORE): release waiting requests based on grouped FIFO. """
        # set volume and deadline to 0 to check first without releasing extra requests
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=0, max_transfers=1, session=self.db_session)

        # one request with an unattached DID -> one request should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name, 1, self.account, session=self.db_session)
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name,
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
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, volume=0, deadline=0, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)

        # one request with an attached DID -> one request should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name = generate_uuid()
        dataset_name = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name, 1, self.account, session=self.db_session)
        add_did(self.scope, dataset_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_name, [{'name': name, 'scope': self.scope}], self.account, session=self.db_session)
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'scope': self.scope,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, volume=0, deadline=0, session=self.db_session)
        request = get_request_by_did(self.scope, name, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)

        # five requests with different requested_at and multiple attachments per collection -> release only one request -> two requests of one collection should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        name4 = generate_uuid()
        name5 = generate_uuid()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        dataset_2_name = generate_uuid()
        add_did(self.scope, dataset_2_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name5, 1, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}, {'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_2_name, [{'name': name3, 'scope': self.scope}, {'name': name4, 'scope': self.scope}], self.account, session=self.db_session)

        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
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
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
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
            'name': name3,
            'requested_at': datetime.now().replace(year=2015),
            'retry_count': 1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
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
            'name': name4,
            'requested_at': datetime.now().replace(year=2010),
            'retry_count': 1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
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
            'name': name5,
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2018),
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, deadline=0, volume=0, session=self.db_session)
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request_1['state'], constants.RequestState.QUEUED)
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request_2['state'], constants.RequestState.QUEUED)
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request_3['state'], constants.RequestState.WAITING)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert_equal(request_4['state'], constants.RequestState.WAITING)
        request_5 = get_request_by_did(self.scope, name5, self.dest_rse_id, session=self.db_session)
        assert_equal(request_5['state'], constants.RequestState.WAITING)

        # with maximal volume check -> release one request -> three requests should be released because of attachments and free volume space
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        dataset_1_name = generate_uuid()
        add_did(self.scope, dataset_1_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name1, 'scope': self.scope}], self.account, session=self.db_session)
        attach_dids(self.scope, dataset_1_name, [{'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=10, max_transfers=1, session=self.db_session)
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
        amount_updated_requests = release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, deadline=0, volume=10, session=self.db_session)
        assert_equal(amount_updated_requests, 3)
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request_1['state'], constants.RequestState.QUEUED)
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request_2['state'], constants.RequestState.QUEUED)
        # released because of available volume
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request_3['state'], constants.RequestState.QUEUED)
        # still waiting because there is no free volume
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert_equal(request_4['state'], constants.RequestState.WAITING)

        # with maximal volume check -> release one request -> two requests should be released because of attachments
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
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
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, volume=5, max_transfers=1, session=self.db_session)
        request = models.Request(dest_rse_id=self.dest_rse_id, bytes=2, activity=self.all_activities, state=constants.RequestState.SUBMITTED)
        request.save(session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
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
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
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
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name3,
            'bytes': 1,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
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
            'name': name4,
            'bytes': 1,
            'requested_at': datetime.now().replace(year=2020),
            'rule_id': generate_uuid(),
            'scope': self.scope,
            'retry_count': 1,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]

        queue_requests(requests, session=self.db_session)
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, deadline=0, volume=5, session=self.db_session)
        # released because it got requested first
        request_1 = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request_1['state'], constants.RequestState.QUEUED)
        # released because the DID is attached to the same dataset
        request_2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request_2['state'], constants.RequestState.QUEUED)
        # still waiting because there is no free volume after releasing the two requests above
        request_3 = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request_3['state'], constants.RequestState.WAITING)
        request_4 = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert_equal(request_4['state'], constants.RequestState.WAITING)

        # with deadline check -> release 0 requests -> 1 request should be released nonetheless
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account)
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account)
        current_hour = datetime.now().hour
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now().replace(hour=current_hour - 2),
            'request_id': generate_uuid(),
            'name': name1,
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
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now(),
            'request_id': generate_uuid(),
            'name': name2,
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
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        release_waiting_requests_grouped_fifo(self.source_rse_id, count=0, deadline=1, volume=0, session=self.db_session)
        # queued because of deadline
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        # waiting because count=0
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)

    def test_release_waiting_requests_fifo(self):
        """ REQUEST (CORE): release waiting requests based on FIFO. """
        # without account and activity check
        # two requests -> release one request -> request with oldest requested_at date should be released
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
        release_waiting_requests_fifo(self.dest_rse_id, count=1, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request2 = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request2['state'], constants.RequestState.WAITING)

        # with activity and account check
        # two requests -> release two request -> requests with correct account and activity should be released
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        name4 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        add_replica(self.source_rse_id, self.scope, name4, 1, self.account, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'source_rse_id': self.source_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'account': self.account,
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
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'account': self.account,
            'attributes': {
                'activity': 'ignore',
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
            'name': name3,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'account': InternalAccount('jdoe', **self.vo),
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
            'requested_at': datetime.now().replace(year=2020),  # requested latest but account and activity are correct
            'name': name4,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'account': self.account,
            'attributes': {
                'activity': self.user_activity,
                'bytes': 1,
                'md5': '',
                'adler32': ''
            }
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_fifo(self.dest_rse_id, count=2, account=self.account, activity=self.user_activity, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)
        request = get_request_by_did(self.scope, name4, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)

    def test_release_waiting_requests_all(self):
        """ REQUEST (CORE): release all waiting requests. """
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
        release_all_waiting_requests(self.dest_rse_id, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)

    def test_release_waiting_requests_per_deadline(self):
        """ REQUEST (CORE): release grouped waiting requests that exceeded waiting time."""
        # a request that exceeded the maximal waiting time to be released (1 hour) -> release one request -> only the exceeded request should be released
        set_rse_transfer_limits(self.source_rse_id, activity=self.all_activities, strategy='grouped_fifo', session=self.db_session)
        name1 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        current_hour = datetime.now().hour
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now().replace(hour=current_hour - 2),
            'request_id': generate_uuid(),
            'name': name1,
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
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now(),
            'request_id': generate_uuid(),
            'name': name2,
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
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        release_waiting_requests_per_deadline(self.source_rse_id, deadline=1, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)

        # a request that exceeded the maximal waiting time to be released (1 hour) -> release one request -> release all requests of the same dataset
        name1 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name1, 1, self.account, session=self.db_session)
        name2 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name2, 1, self.account, session=self.db_session)
        name3 = generate_uuid()
        add_replica(self.source_rse_id, self.scope, name3, 1, self.account, session=self.db_session)
        dataset_name = generate_uuid()
        add_did(self.scope, dataset_name, constants.DIDType.DATASET, self.account, session=self.db_session)
        attach_dids(self.scope, dataset_name, [{'name': name1, 'scope': self.scope}, {'name': name2, 'scope': self.scope}], self.account, session=self.db_session)
        current_hour = datetime.now().hour
        requests = [{
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now().replace(hour=current_hour - 2),
            'request_id': generate_uuid(),
            'name': name1,
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
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now(),
            'request_id': generate_uuid(),
            'name': name2,
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
            'source_rse_id': self.source_rse_id,
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'requested_at': datetime.now(),
            'request_id': generate_uuid(),
            'name': name3,
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
        release_waiting_requests_per_deadline(self.source_rse_id, deadline=1, session=self.db_session)
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name2, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.QUEUED)
        request = get_request_by_did(self.scope, name3, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)


class TestRequestCoreList(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.db_session = session.get_session()
        cls.dest_rse = 'MOCK'
        cls.dest_rse2 = 'MOCK2'
        cls.source_rse = 'MOCK4'
        cls.source_rse2 = 'MOCK5'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.dest_rse_id2 = get_rse_id(cls.dest_rse2, **cls.vo)
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)

    def setUp(self):
        self.db_session.query(models.Source).delete()
        self.db_session.query(models.Request).delete()
        self.db_session.query(models.RSETransferLimit).delete()
        self.db_session.query(models.Distance).delete()
        self.db_session.query(models.Config).delete()
        self.db_session.commit()

    def tearDown(self):
        self.db_session.commit()

    def test_list_requests(self):
        """ REQUEST (CORE): list requests """
        models.Request(state=constants.RequestState.WAITING, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id2, dest_rse_id=self.dest_rse_id).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id2).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id).save(session=self.db_session)

        requests = [request for request in list_requests([self.source_rse_id], [self.dest_rse_id], [constants.RequestState.SUBMITTED], session=self.db_session)]
        assert_equal(len(requests), 2)

        requests = [request for request in list_requests([self.source_rse_id, self.source_rse_id2], [self.dest_rse_id], [constants.RequestState.SUBMITTED], session=self.db_session)]
        assert_equal(len(requests), 3)

        requests = [request for request in list_requests([self.source_rse_id], [self.dest_rse_id], [constants.RequestState.QUEUED], session=self.db_session)]
        assert_equal(len(requests), 0)


class TestRequestREST():

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            cls.vo_header = {'X-Rucio-VO': cls.vo['vo']}
        else:
            cls.vo = {}
            cls.vo_header = {}

        cls.mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(cls.vo_header)
        r1 = TestApp(auth_app.wsgifunc(*cls.mw)).get('/userpass', headers=headers1, expect_errors=True)
        cls.token = str(r1.header('X-Rucio-Auth-Token'))
        cls.source_rse = 'MOCK'
        cls.source_rse_id = get_rse_id(cls.source_rse, **cls.vo)
        cls.source_rse2 = 'MOCK2'
        cls.source_rse_id2 = get_rse_id(cls.source_rse2, **cls.vo)
        cls.source_rse3 = 'MOCK5'
        cls.source_rse_id3 = get_rse_id(cls.source_rse3, **cls.vo)
        cls.dest_rse = 'MOCK3'
        cls.dest_rse_id = get_rse_id(cls.dest_rse, **cls.vo)
        cls.dest_rse2 = 'MOCK4'
        cls.dest_rse_id2 = get_rse_id(cls.dest_rse2, **cls.vo)
        cls.db_session = session.get_session()
        cls.source_site = 'SITE1'
        cls.source_site2 = 'SITE2'
        cls.dst_site = 'SITE3'
        cls.dst_site2 = 'SITE4'
        add_rse_attribute(cls.source_rse_id, 'site', cls.source_site)
        add_rse_attribute(cls.source_rse_id2, 'site', cls.source_site2)
        add_rse_attribute(cls.source_rse_id3, 'site', cls.source_site)
        add_rse_attribute(cls.dest_rse_id, 'site', cls.dst_site)
        add_rse_attribute(cls.dest_rse_id2, 'site', cls.dst_site2)

    def setUp(self):
        self.db_session.query(models.Source).delete()
        self.db_session.query(models.Request).delete()
        self.db_session.commit()

    def check_correct_api(self, params, expected_requests):
        headers = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(self.token)}
        headers.update(self.vo_header)
        r = TestApp(request_app.wsgifunc(*self.mw)).get('/list', params=params, headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        requests = set()
        for request in r.body.decode().split('\n')[:-1]:
            request = parse_response(request)
            requests.add((request['state'], request['source_rse_id'], request['dest_rse_id'], request['name']))
        assert_equal(requests, expected_requests)

    def check_error_api(self, params, exception_class, exception_message, code):
        headers = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(self.token)}
        headers.update(self.vo_header)
        r = TestApp(request_app.wsgifunc(*self.mw)).get('/list', params=params, headers=headers, expect_errors=True)
        body = parse_response(r.body.decode())
        assert_equal(r.status, code)
        assert_equal(body['ExceptionClass'], exception_class)
        assert_equal(body['ExceptionMessage'], exception_message)

    def test_list_requests(self):
        """ REQUEST (REST): list requests """
        name1 = generate_uuid()
        name2 = generate_uuid()
        name3 = generate_uuid()
        models.Request(state=constants.RequestState.WAITING, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id, name=name3).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id2, dest_rse_id=self.dest_rse_id, name=name1).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id2, name=name1).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id, name=name1).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id, dest_rse_id=self.dest_rse_id, name=name2).save(session=self.db_session)
        models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=self.source_rse_id3, dest_rse_id=self.dest_rse_id, name=name2).save(session=self.db_session)
        self.db_session.commit()

        params = {'src_rse': self.source_rse, 'dst_rse': self.dest_rse, 'request_states': 'S'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id, name1))
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id, name2))
        self.check_correct_api(params, expected_requests)

        params = {'src_rse': self.source_rse, 'dst_rse': self.dest_rse, 'request_states': 'Q'}
        expected_requests = set([])
        self.check_correct_api(params, expected_requests)

        params = {'src_rse': self.source_rse2, 'dst_rse': self.dest_rse, 'request_states': 'S'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id2, self.dest_rse_id, name1))
        self.check_correct_api(params, expected_requests)

        params = {'src_rse': self.source_rse, 'dst_rse': self.dest_rse2, 'request_states': 'S'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id2, name1))
        self.check_correct_api(params, expected_requests)

        params = {'src_site': self.source_site, 'dst_site': self.dst_site, 'request_states': 'S'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id, name1))
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id, name2))
        # check correct resolution of site attribute to multiple RSE
        expected_requests.add(('SUBMITTED', self.source_rse_id3, self.dest_rse_id, name2))
        self.check_correct_api(params, expected_requests)

        params = {'src_site': self.source_site, 'dst_site': self.dst_site, 'request_states': 'S,W,Q'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id, name1))
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id, name2))
        expected_requests.add(('WAITING', self.source_rse_id, self.dest_rse_id, name3))
        expected_requests.add(('SUBMITTED', self.source_rse_id3, self.dest_rse_id, name2))
        self.check_correct_api(params, expected_requests)

        params = {'src_site': self.source_site2, 'dst_site': self.dst_site, 'request_states': 'S'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id2, self.dest_rse_id, name1))
        self.check_correct_api(params, expected_requests)

        params = {'src_site': self.source_site, 'dst_site': self.dst_site2, 'request_states': 'S'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id2, name1))
        self.check_correct_api(params, expected_requests)

        params = {'src_site': self.source_site, 'dst_site': self.dst_site2, 'request_states': 'S,W,Q'}
        expected_requests = set()
        expected_requests.add(('SUBMITTED', self.source_rse_id, self.dest_rse_id2, name1))
        self.check_correct_api(params, expected_requests)

        params = {}
        self.check_error_api(params, 'MissingParameter', 'Request state is missing', 400)

        params = {'request_states': 'unkown', 'dst_rse': self.dest_rse, 'src_rse': self.source_rse}
        self.check_error_api(params, 'Invalid', 'Request state value is invalid', 400)

        params = {'request_states': 'S', 'src_rse': self.source_rse}
        self.check_error_api(params, 'MissingParameter', 'Destination RSE is missing', 400)

        params = {'request_states': 'S', 'dst_rse': self.source_rse}
        self.check_error_api(params, 'MissingParameter', 'Source RSE is missing', 400)

        params = {'request_states': 'S', 'src_rse': self.source_rse, 'dst_site': 'SITE'}
        self.check_error_api(params, 'MissingParameter', 'Destination RSE is missing', 400)

        params = {'request_states': 'S', 'src_site': self.source_site}
        self.check_error_api(params, 'MissingParameter', 'Destination site is missing', 400)

        params = {'request_states': 'S', 'dst_site': self.dst_site}
        self.check_error_api(params, 'MissingParameter', 'Source site is missing', 400)

        params = {'request_states': 'S', 'src_site': self.source_site, 'dst_site': 'unknown'}
        self.check_error_api(params, 'NotFound', 'Could not resolve site name unknown to RSE', 404)
