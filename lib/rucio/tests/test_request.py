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
# - Martin Barisits <martin.barisits@cern.ch>, 2019-2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import unittest
from datetime import datetime

import pytest

from rucio.common.config import config_get, config_get_bool, config_set, config_remove_option
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, parse_response
from rucio.core.replica import add_replica
from rucio.core.request import queue_requests, get_request_by_did, list_requests
from rucio.core.rse import get_rse_id, set_rse_transfer_limits, add_rse_attribute
from rucio.db.sqla import session, models, constants
from rucio.db.sqla.constants import RequestType, RequestState
from rucio.tests.common import vohdr, hdrdict, headers, auth


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE, changes global configuration value')
@pytest.mark.parametrize('use_preparer', ['preparer enabled', 'preparer disabled'])
def test_queue_requests_state(vo, use_preparer):
    """ REQUEST (CORE): test queuing requests """

    if use_preparer == 'preparer enabled':
        use_preparer = True
    elif use_preparer == 'preparer disabled':
        use_preparer = False
    else:
        return pytest.xfail(reason=f'unknown test parameter use_preparer={use_preparer}')

    db_session = session.get_session()
    dest_rse = 'MOCK'
    dest_rse2 = 'MOCK2'
    source_rse = 'MOCK4'
    source_rse2 = 'MOCK5'
    dest_rse_id = get_rse_id(dest_rse, vo=vo)
    dest_rse_id2 = get_rse_id(dest_rse2, vo=vo)
    source_rse_id = get_rse_id(source_rse, vo=vo)
    source_rse_id2 = get_rse_id(source_rse2, vo=vo)
    scope = InternalScope('mock', vo=vo)
    account = InternalAccount('root', vo=vo)
    user_activity = 'User Subscription'
    config_set('conveyor', 'use_preparer', str(use_preparer))
    target_state = RequestState.PREPARING if use_preparer else RequestState.QUEUED

    name = generate_uuid()
    name2 = generate_uuid()
    name3 = generate_uuid()
    add_replica(source_rse_id, scope, name, 1, account, session=db_session)
    add_replica(source_rse_id2, scope, name2, 1, account, session=db_session)
    add_replica(source_rse_id, scope, name3, 1, account, session=db_session)

    set_rse_transfer_limits(dest_rse_id, user_activity, max_transfers=1, session=db_session)
    set_rse_transfer_limits(dest_rse_id2, user_activity, max_transfers=1, session=db_session)
    set_rse_transfer_limits(source_rse_id, user_activity, max_transfers=1, session=db_session)
    set_rse_transfer_limits(source_rse_id2, user_activity, max_transfers=1, session=db_session)

    requests = [{
        'dest_rse_id': dest_rse_id,
        'src_rse_id': source_rse_id,
        'request_type': RequestType.TRANSFER,
        'request_id': generate_uuid(),
        'name': name,
        'scope': scope,
        'rule_id': generate_uuid(),
        'retry_count': 1,
        'requested_at': datetime.now().replace(year=2015),
        'attributes': {
            'activity': user_activity,
            'bytes': 10,
            'md5': '',
            'adler32': ''
        }
    }, {
        'dest_rse_id': dest_rse_id,
        'src_rse_id': source_rse_id2,
        'request_type': RequestType.TRANSFER,
        'request_id': generate_uuid(),
        'name': name2,
        'scope': scope,
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
        'dest_rse_id': dest_rse_id2,
        'src_rse_id': source_rse_id,
        'request_type': RequestType.TRANSFER,
        'request_id': generate_uuid(),
        'name': name3,
        'scope': scope,
        'rule_id': generate_uuid(),
        'retry_count': 1,
        'requested_at': datetime.now().replace(year=2015),
        'attributes': {
            'activity': user_activity,
            'bytes': 10,
            'md5': '',
            'adler32': ''
        }
    }]
    try:
        queue_requests(requests, session=db_session)
        request = get_request_by_did(scope, name, dest_rse_id, session=db_session)
        assert request['state'] == target_state
        request = get_request_by_did(scope, name2, dest_rse_id, session=db_session)
        assert request['state'] == target_state
        request = get_request_by_did(scope, name3, dest_rse_id2, session=db_session)
        assert request['state'] == target_state

    finally:
        config_remove_option('conveyor', 'use_preparer')
        db_session.query(models.Source).delete()
        db_session.query(models.Request).delete()
        db_session.query(models.RSETransferLimit).delete()
        db_session.query(models.Distance).delete()
        db_session.query(models.Config).delete()
        db_session.commit()


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestRequestCoreList(unittest.TestCase):

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
        assert len(requests) == 2

        requests = [request for request in list_requests([self.source_rse_id, self.source_rse_id2], [self.dest_rse_id], [constants.RequestState.SUBMITTED], session=self.db_session)]
        assert len(requests) == 3

        requests = [request for request in list_requests([self.source_rse_id], [self.dest_rse_id], [constants.RequestState.QUEUED], session=self.db_session)]
        assert len(requests) == 0


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_list_requests(vo, rest_client, auth_token):
    """ REQUEST (REST): list requests """
    source_rse = 'MOCK'
    source_rse_id = get_rse_id(source_rse, vo=vo)
    source_rse2 = 'MOCK2'
    source_rse_id2 = get_rse_id(source_rse2, vo=vo)
    source_rse3 = 'MOCK5'
    source_rse_id3 = get_rse_id(source_rse3, vo=vo)
    dest_rse = 'MOCK3'
    dest_rse_id = get_rse_id(dest_rse, vo=vo)
    dest_rse2 = 'MOCK4'
    dest_rse_id2 = get_rse_id(dest_rse2, vo=vo)
    db_session = session.get_session()
    source_site = 'SITE1'
    source_site2 = 'SITE2'
    dst_site = 'SITE3'
    dst_site2 = 'SITE4'
    add_rse_attribute(source_rse_id, 'site', source_site)
    add_rse_attribute(source_rse_id2, 'site', source_site2)
    add_rse_attribute(source_rse_id3, 'site', source_site)
    add_rse_attribute(dest_rse_id, 'site', dst_site)
    add_rse_attribute(dest_rse_id2, 'site', dst_site2)

    db_session.query(models.Source).delete()
    db_session.query(models.Request).delete()
    db_session.commit()

    name1 = generate_uuid()
    name2 = generate_uuid()
    name3 = generate_uuid()
    models.Request(state=constants.RequestState.WAITING, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id, name=name3).save(session=db_session)
    models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id2, dest_rse_id=dest_rse_id, name=name1).save(session=db_session)
    models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id2, name=name1).save(session=db_session)
    models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id, name=name1).save(session=db_session)
    models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id, name=name2).save(session=db_session)
    models.Request(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id3, dest_rse_id=dest_rse_id, name=name2).save(session=db_session)
    db_session.commit()

    def check_correct_api(params, expected_requests):
        headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
        response = rest_client.get('/requests/list', query_string=params, headers=headers(auth(auth_token), vohdr(vo), hdrdict(headers_dict)))
        assert response.status_code == 200
        requests = set()
        for request in response.get_data(as_text=True).split('\n')[:-1]:
            request = parse_response(request)
            requests.add((request['state'], request['source_rse_id'], request['dest_rse_id'], request['name']))
        assert requests == expected_requests

    def check_error_api(params, exception_class, exception_message, code):
        headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
        response = rest_client.get('/requests/list', query_string=params, headers=headers(auth(auth_token), vohdr(vo), hdrdict(headers_dict)))
        assert response.status_code == code
        body = parse_response(response.get_data(as_text=True))
        assert body['ExceptionClass'] == exception_class
        assert body['ExceptionMessage'] == exception_message

    params = {'src_rse': source_rse, 'dst_rse': dest_rse, 'request_states': 'S'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id, name1))
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id, name2))
    check_correct_api(params, expected_requests)

    params = {'src_rse': source_rse, 'dst_rse': dest_rse, 'request_states': 'Q'}
    expected_requests = set([])
    check_correct_api(params, expected_requests)

    params = {'src_rse': source_rse2, 'dst_rse': dest_rse, 'request_states': 'S'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id2, dest_rse_id, name1))
    check_correct_api(params, expected_requests)

    params = {'src_rse': source_rse, 'dst_rse': dest_rse2, 'request_states': 'S'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id2, name1))
    check_correct_api(params, expected_requests)

    params = {'src_site': source_site, 'dst_site': dst_site, 'request_states': 'S'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id, name1))
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id, name2))
    # check correct resolution of site attribute to multiple RSE
    expected_requests.add(('SUBMITTED', source_rse_id3, dest_rse_id, name2))
    check_correct_api(params, expected_requests)

    params = {'src_site': source_site, 'dst_site': dst_site, 'request_states': 'S,W,Q'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id, name1))
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id, name2))
    expected_requests.add(('WAITING', source_rse_id, dest_rse_id, name3))
    expected_requests.add(('SUBMITTED', source_rse_id3, dest_rse_id, name2))
    check_correct_api(params, expected_requests)

    params = {'src_site': source_site2, 'dst_site': dst_site, 'request_states': 'S'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id2, dest_rse_id, name1))
    check_correct_api(params, expected_requests)

    params = {'src_site': source_site, 'dst_site': dst_site2, 'request_states': 'S'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id2, name1))
    check_correct_api(params, expected_requests)

    params = {'src_site': source_site, 'dst_site': dst_site2, 'request_states': 'S,W,Q'}
    expected_requests = set()
    expected_requests.add(('SUBMITTED', source_rse_id, dest_rse_id2, name1))
    check_correct_api(params, expected_requests)

    params = {}
    check_error_api(params, 'MissingParameter', 'Request state is missing', 400)

    params = {'request_states': 'unkown', 'dst_rse': dest_rse, 'src_rse': source_rse}
    check_error_api(params, 'Invalid', 'Request state value is invalid', 400)

    params = {'request_states': 'S', 'src_rse': source_rse}
    check_error_api(params, 'MissingParameter', 'Destination RSE is missing', 400)

    params = {'request_states': 'S', 'dst_rse': source_rse}
    check_error_api(params, 'MissingParameter', 'Source RSE is missing', 400)

    params = {'request_states': 'S', 'src_rse': source_rse, 'dst_site': 'SITE'}
    check_error_api(params, 'MissingParameter', 'Destination RSE is missing', 400)

    params = {'request_states': 'S', 'src_site': source_site}
    check_error_api(params, 'MissingParameter', 'Destination site is missing', 400)

    params = {'request_states': 'S', 'dst_site': dst_site}
    check_error_api(params, 'MissingParameter', 'Source site is missing', 400)

    params = {'request_states': 'S', 'src_site': source_site, 'dst_site': 'unknown'}
    check_error_api(params, 'NotFound', 'Could not resolve site name unknown to RSE', 404)
