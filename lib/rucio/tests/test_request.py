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
#
# PY3K COMPATIBLE

from datetime import datetime
from nose.tools import assert_equal

from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import attach_dids, add_did
from rucio.core.replica import add_replica
from rucio.core.request import release_all_waiting_requests, queue_requests, get_request_by_did, release_waiting_requests_per_free_volume, release_waiting_requests_grouped_fifo, release_waiting_requests_fifo
from rucio.core.rse import get_rse_id, set_rse_transfer_limits
from rucio.db.sqla import session, models, constants


class TestRequestCore(object):

    @classmethod
    def setUpClass(cls):
        cls.db_session = session.get_session()
        cls.dialect = cls.db_session.bind.dialect.name
        cls.dest_rse = 'MOCK'
        cls.source_rse = 'MOCK4'
        cls.dest_rse_id = get_rse_id(cls.dest_rse)
        cls.source_rse_id = get_rse_id(cls.source_rse)
        cls.scope = InternalScope('mock')
        cls.account = InternalAccount('root')
        cls.user_activity = 'User Subscription'
        cls.all_activities = 'all_activities'

    def setUp(self):
        self.db_session.query(models.Request).delete()
        self.db_session.commit()
        # set transfer limits to put requests in waiting state
        set_rse_transfer_limits(self.dest_rse_id, self.user_activity, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, self.all_activities, max_transfers=1, session=self.db_session)
        set_rse_transfer_limits(self.dest_rse_id, 'ignore', max_transfers=1, session=self.db_session)

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
        set_rse_transfer_limits(self.dest_rse_id, 'all_activities', volume=volume, max_transfers=1, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
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
        set_rse_transfer_limits(self.dest_rse_id, 'all_activities', volume=volume, max_transfers=1, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name1,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2015),
            'attributes': {
                'activity': 'User Subscription',
                'bytes': 6,
                'md5': '',
                'adler32': ''
            }
        }, {
            'dest_rse_id': self.dest_rse_id,
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
        }, {
            'dest_rse_id': self.dest_rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': name4,
            'scope': self.scope,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now().replace(year=2030),
            'attributes': {
                'activity': 'User Subscription',
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
        set_rse_transfer_limits(self.dest_rse_id, 'all_activities', volume=volume, max_transfers=1, session=self.db_session)
        requests = [{
            'dest_rse_id': self.dest_rse_id,
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
        }]
        queue_requests(requests, session=self.db_session)
        release_waiting_requests_per_free_volume(self.dest_rse_id, volume=volume, session=self.db_session)
        # waiting because no available volume
        request = get_request_by_did(self.scope, name1, self.dest_rse_id, session=self.db_session)
        assert_equal(request['state'], constants.RequestState.WAITING)

    def test_release_waiting_requests_grouped_fifo(self):
        """ REQUEST (CORE): release waiting requests based on grouped FIFO. """
        # set max_volume to 0 to check first without releasing extra requests
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
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, session=self.db_session)
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
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, session=self.db_session)
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
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, session=self.db_session)
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
        amount_updated_requests = release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, session=self.db_session)
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
        release_waiting_requests_grouped_fifo(self.dest_rse_id, count=1, session=self.db_session)
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
            'account': InternalAccount('jdoe'),
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
                'activity': 'User Subscription',
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
                'activity': 'User Subscription',
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
