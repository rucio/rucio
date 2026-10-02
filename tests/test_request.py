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

import importlib
import json
import uuid
from datetime import datetime
from typing import Union

import pytest

import rucio.common.schema
from rucio.common.config import config_get_bool
from rucio.common.constants import RseAttr
from rucio.common.exception import AccessDenied, RSENotFound
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid, parse_response
from rucio.core.distance import add_distance
from rucio.core.replica import add_replica
from rucio.core.request import TransferStatsManager, get_request_by_did, list_requests, list_requests_history, list_requests_history_by_did, queue_requests, set_transfer_limit
from rucio.core.rse import add_rse_attribute
from rucio.db.sqla import constants, models
from rucio.db.sqla.constants import RequestState, RequestType
from rucio.gateway import request as request_gateway
from rucio.tests.common import Mime, accept, auth, did_name_generator, hdrdict, headers, rse_name_generator, vohdr


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
    add_rse_attribute(source_rse_id, RseAttr.SITE, source_site, session=db_session)
    add_rse_attribute(source_rse_id2, RseAttr.SITE, source_site2, session=db_session)
    add_rse_attribute(source_rse_id3, RseAttr.SITE, source_site, session=db_session)
    add_rse_attribute(dest_rse_id, RseAttr.SITE, dst_site, session=db_session)
    add_rse_attribute(dest_rse_id2, RseAttr.SITE, dst_site2, session=db_session)

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


def _add_request_history(
        dest_rse_id,
        scope=None,
        name=None,
        rule_id=None,
        state=RequestState.SUBMITTED,
        created_at=None,
        *,
        session
):
    row = models.RequestHistory(
        scope=scope,
        name=name if name is not None else did_name_generator(),
        dest_rse_id=dest_rse_id,
        rule_id=rule_id,
        state=state,
        created_at=created_at if created_at is not None else datetime.utcnow(),
    )
    row.save(session=session)
    return row


def test_list_history_by_did_returns_latest_first(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    older = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 1), session=db_session
    )
    newer = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 2), session=db_session
    )

    rows = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, session=db_session))
    assert [row.id for row in rows] == [newer.id, older.id]


def test_list_history_by_did_orders_ties_by_id(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    same_time = datetime(2024, 1, 1)
    rows = [_add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=same_time, session=db_session
    ) for _ in range(5)]
    expected = sorted([row.id for row in rows], key=lambda row_id: uuid.UUID(row_id).int, reverse=True)

    result = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, session=db_session))
    assert [row.id for row in result] == expected


def test_list_history_by_did_respects_limit(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    rows = [_add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, i + 1), session=db_session
    ) for i in range(5)]

    result = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, limit=2, session=db_session))
    assert [row.id for row in result] == [rows[4].id, rows[3].id]


def test_list_history_by_did_default_limit_is_10(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    for i in range(11):
        _add_request_history(
            dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, i + 1), session=db_session
        )

    result = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, session=db_session))
    assert len(result) == 10


def test_list_history_by_did_offset_pages_without_overlap(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    rows = [_add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, i + 1), session=db_session
    ) for i in range(4)]

    page1 = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, limit=2, session=db_session))
    page2 = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, offset=2, limit=2, session=db_session))

    assert [row.id for row in page1 + page2] == [rows[3].id, rows[2].id, rows[1].id, rows[0].id]


def test_list_history_by_did_filters_by_rule_id(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    rule_id = generate_uuid()
    matching = _add_request_history(dest_rse_id, scope=mock_scope, name=name, rule_id=rule_id, session=db_session)
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, rule_id=generate_uuid(), session=db_session)

    result = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, rule_id=rule_id, session=db_session))
    assert [row.id for row in result] == [matching.id]


def test_list_history_by_did_filters_by_states(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    failed = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, state=RequestState.FAILED, session=db_session
    )
    waiting = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, state=RequestState.WAITING, session=db_session
    )

    result = list(
        list_requests_history_by_did(mock_scope, name, dest_rse_id, states=[RequestState.FAILED], session=db_session)
    )
    assert [row.id for row in result] == [failed.id]

    result = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, session=db_session))
    assert {row.id for row in result} == {failed.id, waiting.id}


def test_list_history_by_did_created_window_inclusive(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    before = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 1), session=db_session
    )
    lower_bound = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 2), session=db_session
    )
    upper_bound = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 3), session=db_session
    )
    after = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 4), session=db_session
    )

    result = list(list_requests_history_by_did(
        mock_scope, name, dest_rse_id,
        created_after=lower_bound.created_at, created_before=upper_bound.created_at,
        session=db_session,
    ))
    result_ids = {row.id for row in result}
    assert result_ids == {lower_bound.id, upper_bound.id}
    assert before.id not in result_ids
    assert after.id not in result_ids


def test_list_history_by_did_created_after_only(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 1), session=db_session)
    later = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 2), session=db_session
    )
    midpoint = datetime(2024, 1, 1, 12)

    result = list(
        list_requests_history_by_did(mock_scope, name, dest_rse_id, created_after=midpoint, session=db_session)
    )
    assert [row.id for row in result] == [later.id]


def test_list_history_by_did_created_before_only(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    earlier = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 1), session=db_session
    )
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 2), session=db_session)
    midpoint = datetime(2024, 1, 1, 12)

    result = list(
        list_requests_history_by_did(mock_scope, name, dest_rse_id, created_before=midpoint, session=db_session)
    )
    assert [row.id for row in result] == [earlier.id]


def test_list_history_by_did_missing_did_returns_empty(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)

    result = list(list_requests_history_by_did(mock_scope, did_name_generator(), dest_rse_id, session=db_session))
    assert result == []


def test_list_history_by_did_scoped_to_did_and_rse(mock_scope, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    _, other_dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    other_name = did_name_generator()
    matching = _add_request_history(dest_rse_id, scope=mock_scope, name=name, session=db_session)
    _add_request_history(other_dest_rse_id, scope=mock_scope, name=name, session=db_session)
    _add_request_history(dest_rse_id, scope=mock_scope, name=other_name, session=db_session)

    result = list(list_requests_history_by_did(mock_scope, name, dest_rse_id, session=db_session))
    assert [row.id for row in result] == [matching.id]


def test_list_history_by_did_vo_isolation(vo, second_vo, rse_factory, db_session):
    _, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    same_vo_scope = InternalScope('mock', vo=vo)
    other_vo_scope = InternalScope('mock', vo=second_vo)
    matching = _add_request_history(dest_rse_id, scope=same_vo_scope, name=name, session=db_session)
    _add_request_history(dest_rse_id, scope=other_vo_scope, name=name, session=db_session)

    result = list(list_requests_history_by_did(same_vo_scope, name, dest_rse_id, session=db_session))
    assert [row.id for row in result] == [matching.id]


def test_gateway_list_history_by_did_denied_for_plain_account(vo, jdoe_account, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, session=db_session)
    db_session.commit()

    with pytest.raises(AccessDenied):
        list(request_gateway.list_requests_history_by_did(
            scope=mock_scope.external, name=name, rse=dest_rse, issuer=jdoe_account.external, vo=vo,
        ))


def _list_history_by_did_url(scope, name, rse):
    return f'/requests/history/list/{scope}/{name.lstrip("/")}/{rse}'


def _get_list_history_by_did(rest_client, auth_token, vo, scope, name, rse, params=None, mime=Mime.JSON_STREAM):
    return rest_client.get(
        _list_history_by_did_url(scope, name, rse),
        query_string=params or {},
        headers=headers(auth(auth_token), vohdr(vo), accept(mime)),
    )


def _parse_stream(response):
    text = response.get_data(as_text=True)
    if not text:
        return []
    return [parse_response(line) for line in text.split('\n')[:-1]]


def test_api_list_history_by_did_streams_latest_first(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 1), session=db_session)
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 2), session=db_session)
    db_session.commit()

    response = _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, name, dest_rse)
    assert response.status_code == 200
    assert response.content_type == Mime.JSON_STREAM
    rows = _parse_stream(response)
    assert len(rows) == 2
    assert rows[0]['created_at'] > rows[1]['created_at']
    for row in rows:
        assert row['name'] == name
        assert row['dest_rse'] == dest_rse


def test_api_list_history_by_did_default_limit(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    for i in range(11):
        _add_request_history(
            dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, i + 1), session=db_session
        )
    db_session.commit()

    response = _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, name, dest_rse)
    assert response.status_code == 200
    assert len(_parse_stream(response)) == 10


def test_api_list_history_by_did_limit_offset_params(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    seeded = [_add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, i + 1), session=db_session
    ) for i in range(5)]
    db_session.commit()
    newest_first = [row.id for row in reversed(seeded)]

    page1 = _parse_stream(
        _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'limit': 2})
    )
    assert [row['id'] for row in page1] == newest_first[0:2]

    page2 = _parse_stream(
        _get_list_history_by_did(
            rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'limit': 2, 'offset': 2}
        )
    )
    assert [row['id'] for row in page2] == newest_first[2:4]


def test_api_list_history_by_did_rule_id_filter(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    rule_id = generate_uuid()
    matching = _add_request_history(dest_rse_id, scope=mock_scope, name=name, rule_id=rule_id, session=db_session)
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, rule_id=generate_uuid(), session=db_session)
    db_session.commit()

    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'rule_id': rule_id}
    )
    rows = _parse_stream(response)
    assert [row['id'] for row in rows] == [matching.id]


def test_api_list_history_by_did_states_filter(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    failed = _add_request_history(dest_rse_id, scope=mock_scope, name=name, state=RequestState.FAILED, session=db_session)
    waiting = _add_request_history(dest_rse_id, scope=mock_scope, name=name, state=RequestState.WAITING, session=db_session)
    submitted = _add_request_history(dest_rse_id, scope=mock_scope, name=name, state=RequestState.SUBMITTED, session=db_session)
    db_session.commit()

    rows = _parse_stream(
        _get_list_history_by_did(
            rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'request_states': 'F'}
        )
    )
    assert [row['id'] for row in rows] == [failed.id]

    rows = _parse_stream(
        _get_list_history_by_did(
            rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'request_states': 'F,S'}
        )
    )
    assert {row['id'] for row in rows} == {failed.id, submitted.id}

    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'request_states': 'F,unknown'}
    )
    assert response.status_code == 400
    body = parse_response(response.get_data(as_text=True))
    assert body['ExceptionClass'] == 'Invalid'

    rows = _parse_stream(_get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, name, dest_rse))
    assert {row['id'] for row in rows} == {failed.id, waiting.id, submitted.id}


def test_api_list_history_by_did_bad_state_returns_400(vo, rest_client, auth_token, mock_scope):
    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, did_name_generator(), rse_name_generator(),
        params={'request_states': 'unknown'}
    )
    assert response.status_code == 400
    body = parse_response(response.get_data(as_text=True))
    assert body['ExceptionClass'] == 'Invalid'


def test_api_list_history_by_did_created_window(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    earlier = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 1), session=db_session
    )
    later = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 2), session=db_session
    )
    db_session.commit()
    midpoint = datetime(2024, 1, 1, 12).strftime('%Y-%m-%dT%H:%M:%S')

    rows = _parse_stream(
        _get_list_history_by_did(
            rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'created_after': midpoint}
        )
    )
    assert [row['id'] for row in rows] == [later.id]

    rows = _parse_stream(
        _get_list_history_by_did(
            rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'created_before': midpoint}
        )
    )
    assert [row['id'] for row in rows] == [earlier.id]


def test_api_list_history_by_did_bad_date_returns_400(vo, rest_client, auth_token, mock_scope):
    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, did_name_generator(), rse_name_generator(),
        params={'created_after': 'not-a-date'}
    )
    assert response.status_code == 400
    body = parse_response(response.get_data(as_text=True))
    assert body['ExceptionClass'] == 'Invalid'


def test_api_list_history_by_did_bad_rule_id_returns_400(vo, rest_client, auth_token, mock_scope):
    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, did_name_generator(), rse_name_generator(),
        params={'rule_id': 'not-a-uuid'}
    )
    assert response.status_code == 400
    body = parse_response(response.get_data(as_text=True))
    assert body['ExceptionClass'] == 'Invalid'


@pytest.mark.parametrize(
    "params",
    [{'limit': 0}, {'limit': -1}, {'offset': -1}, {'limit': 2 ** 63}, {'offset': 2 ** 63}, {'limit': 'abc'}, {'offset': 'abc'}]
)
def test_api_list_history_by_did_invalid_limit_offset_returns_400(params, vo, rest_client, auth_token, mock_scope):
    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, did_name_generator(), rse_name_generator(), params=params
    )
    assert response.status_code == 400
    body = parse_response(response.get_data(as_text=True))
    assert body['ExceptionClass'] == 'Invalid'


def test_api_list_history_by_did_empty_limit_offset_use_defaults(vo, rest_client, auth_token, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    for i in range(11):
        _add_request_history(
            dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, i + 1), session=db_session
        )
    db_session.commit()

    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, name, dest_rse, params={'limit': '', 'offset': ''}
    )
    assert response.status_code == 200
    assert len(_parse_stream(response)) == 10


def test_api_list_history_by_did_unknown_rse_returns_404(vo, rest_client, auth_token, mock_scope):
    response = _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, did_name_generator(), rse_name_generator())
    assert response.status_code == 404


def test_api_list_history_by_did_bad_scope_name_returns_400(vo, rest_client, auth_token, rse_factory):
    dest_rse, _ = rse_factory.make_mock_rse()

    response = rest_client.get(
        f'/requests/history/list/{generate_uuid()}/{dest_rse}',
        headers=headers(auth(auth_token), vohdr(vo), accept(Mime.JSON_STREAM)),
    )
    assert response.status_code == 400


def test_api_list_history_by_did_empty_returns_200_empty_body(vo, rest_client, auth_token, rse_factory, mock_scope):
    dest_rse, _ = rse_factory.make_mock_rse()

    response = _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, did_name_generator(), dest_rse)
    assert response.status_code == 200
    assert response.get_data(as_text=True) == ''


def test_api_list_history_by_did_wrong_accept_returns_406(vo, rest_client, auth_token, rse_factory, mock_scope):
    dest_rse, _ = rse_factory.make_mock_rse()

    response = _get_list_history_by_did(
        rest_client, auth_token, vo, mock_scope.external, did_name_generator(), dest_rse, mime=Mime.JSON
    )
    assert response.status_code == 406


@pytest.mark.noparallel(reason='temporarily replaces the VO schema module')
def test_api_list_history_by_did_slash_in_name_first_slash_schema(vo, rest_client, auth_token, rse_factory, mock_scope, db_session, monkeypatch):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = f'dir/{generate_uuid()}'
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, session=db_session)
    db_session.commit()

    # the generic schema's SCOPE_NAME_REGEXP splits on the first slash
    monkeypatch.setitem(rucio.common.schema.schema_modules, vo, importlib.import_module('rucio.common.schema.generic'))
    response = _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, name, dest_rse)

    assert response.status_code == 200
    assert [row['name'] for row in _parse_stream(response)] == [name]


@pytest.mark.noparallel(reason='temporarily replaces the VO schema module')
def test_api_list_history_by_did_slash_in_name_last_slash_schema(vo, rest_client, auth_token, rse_factory, mock_scope, db_session, monkeypatch):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = f'dir/{generate_uuid()}'
    _add_request_history(dest_rse_id, scope=mock_scope, name=name, session=db_session)
    db_session.commit()

    # the multi-VO schema's SCOPE_NAME_REGEXP splits on the last slash
    monkeypatch.setitem(rucio.common.schema.schema_modules, vo, importlib.import_module('rucio.common.schema.generic_multi_vo'))
    response = _get_list_history_by_did(rest_client, auth_token, vo, mock_scope.external, name, dest_rse)

    assert response.status_code == 200
    assert _parse_stream(response) == []


def test_client_list_history_by_did_end_to_end(rucio_client, rse_factory, mock_scope, db_session):
    dest_rse, dest_rse_id = rse_factory.make_mock_rse(session=db_session)
    name = did_name_generator()
    _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, state=RequestState.FAILED, created_at=datetime(2024, 1, 1),
        session=db_session
    )
    older_failed = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, state=RequestState.FAILED, created_at=datetime(2024, 1, 2),
        session=db_session
    )
    newest_submitted = _add_request_history(
        dest_rse_id, scope=mock_scope, name=name, created_at=datetime(2024, 1, 3), session=db_session
    )
    db_session.commit()

    rows = list(rucio_client.list_requests_history_by_did(
        name=name,
        rse=dest_rse,
        scope=mock_scope.external,
        request_states=['F', 'S'],
        created_after=datetime(2023, 12, 31),
        created_before=datetime(2024, 1, 4),
        limit=2,
    ))
    assert [row['id'] for row in rows] == [newest_submitted.id, older_failed.id]
    assert isinstance(rows[0]['created_at'], datetime)


def test_client_list_history_by_did_unknown_rse_raises(rucio_client, mock_scope):
    with pytest.raises(RSENotFound):
        rucio_client.list_requests_history_by_did(name=did_name_generator(), rse=rse_name_generator(), scope=mock_scope.external)
