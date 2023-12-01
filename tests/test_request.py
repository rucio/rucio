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

import json
from datetime import datetime
from typing import Union

import pytest

from rucio.common.config import config_get_bool
from rucio.common.utils import generate_uuid, parse_response
from rucio.core.distance import add_distance
from rucio.core.replica import add_replica
from rucio.core.request import queue_requests, get_request_by_did, list_requests, list_requests_history, set_transfer_limit, TransferStatsManager
from rucio.core.rse import add_rse_attribute
from rucio.db.sqla import models, constants
from rucio.db.sqla.constants import RequestType, RequestState
from rucio.tests.common import vohdr, hdrdict, headers, auth


@pytest.mark.parametrize("file_config_mock", [
    # Run test twice: with, and without, preparer enabled
    {
        "overrides": [
            ('conveyor', 'use_preparer', 'true')
        ]
    },
    {
        "overrides": [
            ('conveyor', 'use_preparer', 'false')
        ]
    }
], indirect=True)
def test_queue_requests_state(vo, file_config_mock, rse_factory, mock_scope, root_account, db_session):
    """ REQUEST (CORE): test queuing requests """

    source_rse, source_rse_id = rse_factory.make_mock_rse(session=db_session)
    source_rse2, source_rse_id2 = rse_factory.make_mock_rse(session=db_session)
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    dest_rse2, dest_rse_id2 = rse_factory.make_mock_rse(session=db_session)

    user_activity = 'User Subscription'
    use_preparer = config_get_bool('conveyor', 'use_preparer', session=db_session)
    target_state = RequestState.PREPARING if use_preparer else RequestState.QUEUED

    name = generate_uuid()
    name2 = generate_uuid()
    name3 = generate_uuid()
    add_replica(source_rse_id, mock_scope, name, 1, root_account, session=db_session)
    add_replica(source_rse_id2, mock_scope, name2, 1, root_account, session=db_session)
    add_replica(source_rse_id, mock_scope, name3, 1, root_account, session=db_session)

    set_transfer_limit(dest_rse, user_activity, max_transfers=1, session=db_session)
    set_transfer_limit(dest_rse2, user_activity, max_transfers=1, session=db_session)
    set_transfer_limit(source_rse, user_activity, max_transfers=1, session=db_session)
    set_transfer_limit(source_rse2, user_activity, max_transfers=1, session=db_session)

    requests = [{
        'dest_rse_id': dest_rse_id,
        'src_rse_id': source_rse_id,
        'request_type': RequestType.TRANSFER,
        'request_id': generate_uuid(),
        'name': name,
        'scope': mock_scope,
        'rule_id': generate_uuid(),
        'retry_count': 1,
        'requested_at': datetime.utcnow().replace(year=2015),
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
        'scope': mock_scope,
        'rule_id': generate_uuid(),
        'retry_count': 1,
        'requested_at': datetime.utcnow().replace(year=2015),
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
        'scope': mock_scope,
        'rule_id': generate_uuid(),
        'retry_count': 1,
        'requested_at': datetime.utcnow().replace(year=2015),
        'attributes': {
            'activity': user_activity,
            'bytes': 10,
            'md5': '',
            'adler32': ''
        }
    }]
    queue_requests(requests, session=db_session)
    request = get_request_by_did(mock_scope, name, dest_rse_id, session=db_session)
    assert request['state'] == target_state
    request = get_request_by_did(mock_scope, name2, dest_rse_id, session=db_session)
    assert request['state'] == target_state
    request = get_request_by_did(mock_scope, name3, dest_rse_id2, session=db_session)
    assert request['state'] == target_state


@pytest.mark.parametrize(
    "model,list_fnc", [
        (models.Request, list_requests),
        (models.RequestHistory, list_requests_history),
    ]
)
def test_core_list(model: Union[type[models.Request], type[models.RequestHistory]], list_fnc, rse_factory, db_session):
    """ REQUEST (CORE): Test listing requests and request history via the core"""
    _, source_rse_id = rse_factory.make_mock_rse(session=db_session)
    _, source_rse_id2 = rse_factory.make_mock_rse(session=db_session)
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    _, dest_rse_id2 = rse_factory.make_mock_rse(session=db_session)
    model(state=constants.RequestState.WAITING, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id2, dest_rse_id=dest_rse_id).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id2).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id).save(session=db_session)

    requests = [request for request in list_fnc([source_rse_id], [dest_rse_id], [constants.RequestState.SUBMITTED], session=db_session)]
    assert len(requests) == 2

    requests = [request for request in list_fnc([source_rse_id, source_rse_id2], [dest_rse_id], [constants.RequestState.SUBMITTED], session=db_session)]
    assert len(requests) == 3

    requests = [request for request in list_fnc([source_rse_id], [dest_rse_id], [constants.RequestState.QUEUED], session=db_session)]
    assert len(requests) == 0


@pytest.mark.parametrize(
    "model,api_endpoint", [
        (models.Request, '/requests/list'),
        (models.RequestHistory, '/requests/history/list'),
    ]
)
def test_api_list(
        vo,
        model: Union[type[models.Request], type[models.RequestHistory]],
        api_endpoint: str,
        rest_client,
        auth_token,
        rse_factory,
        tag_factory,
        db_session
):
    """ REQUEST (REST): Test listing requests and request history via the api"""
    source_rse, source_rse_id = rse_factory.make_mock_rse(session=db_session)
    source_rse2, source_rse_id2 = rse_factory.make_mock_rse(session=db_session)
    source_rse3, source_rse_id3 = rse_factory.make_mock_rse(session=db_session)
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    dest_rse2, dest_rse_id2 = rse_factory.make_mock_rse(session=db_session)
    source_site = tag_factory.new_tag()
    source_site2 = tag_factory.new_tag()
    dst_site = tag_factory.new_tag()
    dst_site2 = tag_factory.new_tag()
    add_rse_attribute(source_rse_id, 'site', source_site, session=db_session)
    add_rse_attribute(source_rse_id2, 'site', source_site2, session=db_session)
    add_rse_attribute(source_rse_id3, 'site', source_site, session=db_session)
    add_rse_attribute(dest_rse_id, 'site', dst_site, session=db_session)
    add_rse_attribute(dest_rse_id2, 'site', dst_site2, session=db_session)

    name1 = generate_uuid()
    name2 = generate_uuid()
    name3 = generate_uuid()
    model(state=constants.RequestState.WAITING, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id, name=name3).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id2, dest_rse_id=dest_rse_id, name=name1).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id2, name=name1).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id, name=name1).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id, dest_rse_id=dest_rse_id, name=name2).save(session=db_session)
    model(state=constants.RequestState.SUBMITTED, source_rse_id=source_rse_id3, dest_rse_id=dest_rse_id, name=name2).save(session=db_session)
    db_session.commit()

    def check_correct_api(params, expected_requests):
        headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
        response = rest_client.get(api_endpoint, query_string=params, headers=headers(auth(auth_token), vohdr(vo), hdrdict(headers_dict)))
        assert response.status_code == 200
        requests = set()
        for request in response.get_data(as_text=True).split('\n')[:-1]:
            request = parse_response(request)
            requests.add((request['state'], request['source_rse_id'], request['dest_rse_id'], request['name']))
        assert requests == expected_requests

    def check_error_api(params, exception_class, exception_message, code):
        headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
        response = rest_client.get(api_endpoint, query_string=params, headers=headers(auth(auth_token), vohdr(vo), hdrdict(headers_dict)))
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

    params = {'request_states': 'S', 'src_rse': source_rse, 'dst_site': dst_site}
    check_error_api(params, 'MissingParameter', 'Destination RSE is missing', 400)

    params = {'request_states': 'S', 'src_site': source_site}
    check_error_api(params, 'MissingParameter', 'Destination site is missing', 400)

    params = {'request_states': 'S', 'dst_site': dst_site}
    check_error_api(params, 'MissingParameter', 'Source site is missing', 400)

    params = {'request_states': 'S', 'src_site': source_site, 'dst_site': 'unknown'}
    check_error_api(params, 'NotFound', 'Could not resolve site name unknown to RSE', 404)


@pytest.mark.parametrize("file_config_mock", [{"overrides": [
    ('transfers', 'stats_enabled', 'True'),
]}], indirect=True)
def test_api_metrics(vo, rest_client, auth_token, rse_factory, did_factory, root_account, file_config_mock):

    src_rse, src_rse_id = rse_factory.make_mock_rse()
    dst_rse, dst_rse_id = rse_factory.make_mock_rse()
    add_distance(src_rse_id, dst_rse_id, distance=10)

    replica_bytes = 20

    did1 = did_factory.random_file_did()
    activity1 = 'User Subscription'
    add_replica(rse_id=src_rse_id, bytes_=replica_bytes, adler32='beefdead', account=root_account, **did1)

    did2 = did_factory.random_file_did()
    activity2 = 'Test'
    add_replica(rse_id=src_rse_id, bytes_=replica_bytes, adler32='beefdead', account=root_account, **did2)

    requests = [
        {
            'dest_rse_id': dst_rse_id,
            'source_rse_id': src_rse_id,
            'request_type': RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': did1['name'],
            'scope': did1['scope'],
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'attributes': {
                'activity': activity,
                'bytes': replica_bytes,
                'md5': '',
                'adler32': ''
            }
        }
        for did, activity in ((did1, activity1), (did2, activity2))
    ]
    queue_requests(requests)

    stats_manager = TransferStatsManager()
    stats_manager.observe(
        src_rse_id=src_rse_id,
        dst_rse_id=dst_rse_id,
        activity=activity1,
        state=RequestState.DONE,
        file_size=367,
    )
    stats_manager.observe(
        src_rse_id=src_rse_id,
        dst_rse_id=dst_rse_id,
        activity=activity2,
        state=RequestState.FAILED,
        file_size=1020,
    )
    stats_manager.force_save()
    stats_manager.downsample_and_cleanup()

    api_endpoint = '/requests/metrics'
    params = {'dst_rse': dst_rse, 'src_rse': src_rse}
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': root_account.external}
    response = rest_client.get(api_endpoint, query_string=params, headers=headers(auth(auth_token), vohdr(vo), hdrdict(headers_dict)))
    metric = json.loads(response.get_data(as_text=True))
    assert metric['distance'] == 10
    assert metric['bytes']['queued'][activity1] == replica_bytes
    assert metric['bytes']['queued'][activity2] == replica_bytes
    assert metric['bytes']['queued-total'] == 2 * replica_bytes
    assert metric['files']['queued'][activity1] == 1
    assert metric['files']['queued'][activity2] == 1
    assert metric['files']['queued-total'] == 2
    assert metric['files']['done'][activity1]['1h'] == 1
    assert metric['bytes']['done'][activity1]['1h'] == 367
    assert metric['files']['failed'][activity2]['1h'] == 1
    assert metric['src_rse'] == src_rse
    assert metric['dst_rse'] == dst_rse

    params = {'dst_rse': dst_rse, 'src_rse': src_rse, 'format': 'panda'}
    response = rest_client.get(api_endpoint, query_string=params, headers=headers(auth(auth_token), vohdr(vo), hdrdict(headers_dict)))
    response = json.loads(response.get_data(as_text=True))
    metric = response.get(f'{src_rse}:{dst_rse}')
    assert metric is not None
