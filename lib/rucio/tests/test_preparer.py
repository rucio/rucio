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


import pytest

from rucio.core.distance import get_distances, add_distance
from rucio.core.replica import add_replicas
from rucio.core.request import list_transfer_requests_and_source_replicas
from rucio.core.transfer import get_supported_transfertools
from rucio.core.rse import set_rse_transfer_limits, add_rse_attribute, RseData
from rucio.daemons.conveyor import preparer
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState


@pytest.fixture
def dest_rse(vo, rse_factory):
    rse_name, rse_id = rse_factory.make_mock_rse()
    yield {'name': rse_name, 'id': rse_id}


@pytest.fixture
def source_rse(vo, rse_factory, dest_rse):
    rse_name, rse_id = rse_factory.make_mock_rse()
    add_distance(rse_id, dest_rse['id'], ranking=5)
    yield {'name': rse_name, 'id': rse_id}


@pytest.fixture
def file(vo, did_factory):
    did = did_factory.random_file_did()
    return {'scope': did['scope'], 'name': did['name'], 'bytes': 1, 'adler32': 'deadbeef'}


@pytest.fixture
def dataset(db_session, did_factory, vo):
    return did_factory.make_dataset()


@pytest.fixture
def mock_request(db_session, vo, source_rse, dest_rse, file, root_account):
    add_replicas(rse_id=source_rse['id'], files=[file], account=root_account, session=db_session)

    request = models.Request(
        state=RequestState.PREPARING,
        scope=file['scope'],
        name=file['name'],
        dest_rse_id=dest_rse['id'],
        account=root_account,
    )
    request.save(session=db_session)
    request_dict = request.to_dict()
    db_session.commit()
    db_session.expunge(request)
    yield request_dict


@pytest.fixture
def mock_request_no_source(db_session, dest_rse, dataset, root_account):
    request = models.Request(
        state=RequestState.PREPARING,
        scope=dataset['scope'],
        name=dataset['name'],
        dest_rse_id=dest_rse['id'],
        account=root_account,
    )
    request.save(session=db_session)
    request_dict = request.to_dict()
    db_session.commit()
    db_session.expunge(request)
    yield request_dict


def test_listing_preparing_transfers(mock_request):
    req_sources = list_transfer_requests_and_source_replicas(request_state=RequestState.PREPARING)

    assert len(req_sources) != 0
    found_requests = list(filter(lambda rws: rws.request_id == mock_request['id'], req_sources.values()))
    assert len(found_requests) == 1


@pytest.mark.noparallel(reason='uses preparer')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('throttler', 'mode', 'DEST_PER_ACT')
]}], indirect=True)
def test_preparer_setting_request_state_waiting(db_session, mock_request, core_config_mock):
    set_rse_transfer_limits(
        mock_request['dest_rse_id'],
        activity=mock_request['activity'],
        max_transfers=1,
        strategy='fifo',
    )

    preparer.run_once(logger=print)

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request['id']).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.WAITING


@pytest.mark.noparallel(reason='uses preparer')
def test_preparer_setting_request_state_queued(db_session, mock_request):
    preparer.run_once(logger=print)

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request['id']).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED


@pytest.mark.noparallel(reason='uses preparer')
def test_preparer_setting_request_source(db_session, vo, source_rse, mock_request):
    preparer.run_once(logger=print)

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request['id']).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED
    assert updated_mock_request.source_rse_id == source_rse['id']


@pytest.mark.noparallel(reason='uses preparer')
def test_preparer_for_request_without_source(db_session, mock_request_no_source):
    preparer.run_once(logger=print)

    updated_mock_request: "models.Request" = (
        db_session.query(models.Request).filter_by(id=mock_request_no_source['id']).one()
    )

    assert updated_mock_request.state == RequestState.NO_SOURCES


@pytest.mark.noparallel(reason='uses preparer')
def test_preparer_without_and_with_mat(db_session, source_rse, dest_rse, mock_request):
    add_rse_attribute(source_rse['id'], 'fts', 'a')
    add_rse_attribute(dest_rse['id'], 'globus_endpoint_id', 'b')

    from rucio.core.rse import REGION

    REGION.invalidate()

    preparer.run_once(logger=print, transfertools=['fts3', 'globus'])

    db_session.expunge_all()
    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request['id']).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.NO_SOURCES


@pytest.mark.noparallel(reason='uses preparer')
def test_two_sources_one_destination(rse_factory, source_rse, db_session, vo, file, mock_request):
    _, source_rse2_id = rse_factory.make_mock_rse()
    add_distance(source_rse2_id, mock_request['dest_rse_id'], ranking=2)
    add_replicas(rse_id=source_rse2_id, files=[file], account=mock_request['account'])

    src1_distance, src2_distance = (
        get_distances(
            src_rse_id=src_rse,
            dest_rse_id=mock_request['dest_rse_id'],
        )
        for src_rse in (source_rse['id'], source_rse2_id)
    )
    assert src1_distance and len(src1_distance) == 1 and src1_distance[0]['ranking'] == 5
    assert src2_distance and len(src2_distance) == 1 and src2_distance[0]['ranking'] == 2

    preparer.run_once(logger=print)

    db_session.expunge_all()
    updated_mock_request = (
        db_session.query(models.Request).filter_by(id=mock_request['id']).one()
    )  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED
    assert updated_mock_request.source_rse_id == source_rse2_id  # distance 2 < 5


def test_get_supported_transfertools_none(vo, rse_factory):
    source_rse, source_rse_id = rse_factory.make_mock_rse()
    dest_rse, dest_rse_id = rse_factory.make_mock_rse()

    transfertools = get_supported_transfertools(source_rse=RseData(source_rse_id), dest_rse=RseData(dest_rse_id), transfertools=['fts3', 'globus'])

    assert not transfertools


def test_get_supported_transfertools_fts_globus(vo, rse_factory):
    source_rse, source_rse_id = rse_factory.make_mock_rse()
    dest_rse, dest_rse_id = rse_factory.make_mock_rse()

    add_rse_attribute(source_rse_id, 'fts', 'a')
    add_rse_attribute(dest_rse_id, 'fts', 'b')
    add_rse_attribute(source_rse_id, 'globus_endpoint_id', 'a')
    add_rse_attribute(dest_rse_id, 'globus_endpoint_id', 'b')

    transfertools = get_supported_transfertools(source_rse=RseData(source_rse_id), dest_rse=RseData(dest_rse_id), transfertools=['fts3', 'globus'])

    assert len(transfertools) == 2
    assert 'fts3' in transfertools
    assert 'globus' in transfertools
