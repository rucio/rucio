# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import pytest

from rucio.common.types import InternalScope, InternalAccount
from rucio.common.utils import generate_uuid
from rucio.core import config
from rucio.core.distance import get_distances, add_distance
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import get_rse_id, set_rse_transfer_limits, add_rse, del_rse
from rucio.core.transfer import __list_transfer_requests_and_source_replicas
from rucio.daemons.conveyor import preparer
from rucio.db.sqla import models, session
from rucio.db.sqla.constants import RequestState
from rucio.tests.common import rse_name_generator


@pytest.fixture
def db_session():
    db_session = session.get_session()
    yield db_session
    db_session.rollback()


@pytest.fixture(scope='module')
def dest_rse(vo):
    dest_rse = 'MOCK'
    dest_rse_id = get_rse_id(dest_rse, vo=vo)
    return {'name': dest_rse, 'id': dest_rse_id}


def generate_rse(vo='def', session=None):
    rse_name = f'MOCK-{rse_name_generator()}'
    rse_id = add_rse(rse_name, vo=vo, session=session)
    return {'name': rse_name, 'id': rse_id}


@pytest.fixture
def source_rse(db_session, vo, dest_rse):
    rse = generate_rse(vo=vo, session=db_session)
    add_distance(rse['id'], dest_rse['id'], ranking=5, session=db_session)
    db_session.commit()

    yield rse

    del_rse(rse['id'], session=db_session)
    db_session.commit()


@pytest.fixture
def file(vo):
    scope = InternalScope(scope='mock', vo=vo)
    name = generate_uuid()
    return {'scope': scope, 'name': name, 'bytes': 1, 'adler32': 'deadbeef'}


@pytest.fixture
def mock_request(db_session, vo, source_rse, dest_rse, file):
    account = InternalAccount('root', vo=vo)

    add_replicas(rse_id=source_rse['id'], files=[file], account=account, session=db_session)

    request = models.Request(state=RequestState.PREPARING, scope=file['scope'], name=file['name'], dest_rse_id=dest_rse['id'], account=account)
    request.save(session=db_session)
    db_session.commit()

    yield request

    request.delete(session=db_session)
    delete_replicas(rse_id=source_rse['id'], files=[file], session=db_session)
    db_session.commit()


@pytest.fixture
def dest_throttler(db_session, mock_request):
    config.set('throttler', 'mode', 'DEST_PER_ACT', session=db_session)
    set_rse_transfer_limits(mock_request.dest_rse_id, activity=mock_request.activity, max_transfers=1, strategy='fifo', session=db_session)
    db_session.commit()

    yield

    db_session.query(models.RSETransferLimit).filter_by(rse_id=mock_request.dest_rse_id).delete()
    config.remove_option('throttler', 'mode', session=db_session)
    db_session.commit()


def test_listing_preparing_transfers(db_session, mock_request):
    req_sources = __list_transfer_requests_and_source_replicas(request_state=RequestState.PREPARING, session=db_session)

    assert len(req_sources) == 1
    req_id = req_sources[0][0]
    assert req_id == mock_request.id


@pytest.mark.usefixtures('dest_throttler')
def test_preparer_setting_request_state_waiting(db_session, mock_request):
    preparer.run_once(session=db_session)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.WAITING


def test_preparer_setting_request_state_queued(db_session, mock_request):
    preparer.run_once(session=db_session)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED


def test_preparer_setting_request_source(db_session, vo, source_rse, mock_request):
    preparer.run_once(session=db_session)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED
    assert updated_mock_request.source_rse_id == source_rse['id']


@pytest.fixture
def source2_rse(db_session, vo, dest_rse):
    rse = generate_rse(vo=vo)
    add_distance(rse['id'], dest_rse['id'], ranking=2, session=db_session)
    db_session.commit()

    yield rse

    del_rse(rse['id'], session=db_session)
    db_session.commit()


def test_two_sources_one_destination(db_session, vo, file, source_rse, source2_rse, mock_request):
    add_replicas(rse_id=source2_rse['id'], files=[file], account=mock_request.account, session=db_session)
    try:
        src1_distance, src2_distance = (get_distances(
            src_rse_id=src_rse,
            dest_rse_id=mock_request.dest_rse_id,
            session=db_session
        ) for src_rse in (source_rse['id'], source2_rse['id']))

        assert src1_distance and len(src1_distance) == 1 and src1_distance[0]['ranking'] == 5
        assert src2_distance and len(src2_distance) == 1 and src2_distance[0]['ranking'] == 2

        preparer.run_once(session=db_session)
        db_session.commit()

        updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

        assert updated_mock_request.state == RequestState.QUEUED
        assert updated_mock_request.source_rse_id == source2_rse['id']  # distance 2 < 5

    finally:
        delete_replicas(rse_id=source2_rse['id'], files=[file], session=db_session)
        db_session.commit()
