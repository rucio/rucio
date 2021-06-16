# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from typing import TYPE_CHECKING

import pytest

from rucio.common.types import InternalScope, InternalAccount
from rucio.common.utils import generate_uuid
from rucio.core import config as rucio_config
from rucio.core.did import add_did, delete_dids
from rucio.core.distance import get_distances, add_distance
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.request import sort_requests_minimum_distance, get_transfertool_filter, get_supported_transfertools
from rucio.core.rse import set_rse_transfer_limits, add_rse, del_rse, add_rse_attribute
from rucio.core.transfer import __list_transfer_requests_and_source_replicas
from rucio.daemons.conveyor import preparer
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, DIDType
from rucio.db.sqla.session import get_session
from rucio.tests.common import rse_name_generator

if TYPE_CHECKING:
    from typing import Set, Optional, Callable
    from sqlalchemy.orm import Session


class GeneratedRSE:
    def __init__(
        self,
        vo: str,
        db_session: "Session",
        setup_func: "Optional[Callable]" = None,
        teardown_func: "Optional[Callable]" = None,
    ):
        self.vo = vo
        self.db_session = db_session
        self.setup = setup_func
        self.teardown = teardown_func
        self.name = rse_name_generator()
        self.rse_id: "Optional[str]" = None

    def __enter__(self):
        self.rse_id = add_rse(self.name, vo=self.vo, session=self.db_session)
        if self.setup:
            self.setup(self)
        self.db_session.commit()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        del_rse(rse_id=self.rse_id, session=self.db_session)
        if self.teardown:
            self.teardown(self)
        self.db_session.commit()


class GeneratedRequest:
    def __init__(
        self,
        scope: "InternalScope",
        name: str,
        dest_rse_id: str,
        account: "InternalAccount",
        db_session: "Session",
        setup_func: "Optional[Callable]" = None,
        teardown_func: "Optional[Callable]" = None,
    ):
        self.db_session = db_session
        self.setup = setup_func
        self.teardown = teardown_func
        self.db_object = models.Request(
            state=RequestState.PREPARING,
            scope=scope,
            name=name,
            dest_rse_id=dest_rse_id,
            account=account,
        )

    def __enter__(self):
        self.db_object.save(session=self.db_session)
        if self.setup:
            self.setup(self)
        self.db_session.commit()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db_object.delete(session=self.db_session)
        if self.teardown:
            self.teardown(self)
        self.db_session.commit()


@pytest.fixture
def db_session():
    db_session = get_session()
    yield db_session
    db_session.rollback()


@pytest.fixture
def dest_rse(vo, db_session):
    with GeneratedRSE(vo=vo, db_session=db_session) as generated_rse:
        yield {'name': generated_rse.name, 'id': generated_rse.rse_id}


@pytest.fixture
def source_rse(vo, dest_rse, db_session):
    def setup(rse):
        add_distance(rse.rse_id, dest_rse['id'], ranking=5, session=rse.db_session)

    with GeneratedRSE(vo=vo, db_session=db_session, setup_func=setup) as generated_rse:
        yield {'name': generated_rse.name, 'id': generated_rse.rse_id}


@pytest.fixture
def file(vo):
    scope = InternalScope(scope='mock', vo=vo)
    name = generate_uuid()
    return {'scope': scope, 'name': name, 'bytes': 1, 'adler32': 'deadbeef'}


@pytest.fixture
def dataset(db_session, vo):
    scope = InternalScope(scope='mock', vo=vo)
    name = generate_uuid()
    account = InternalAccount('root', vo=vo)

    kwargs = {'scope': scope, 'name': name, 'type': DIDType.DATASET, 'account': account}
    add_did(**kwargs, session=db_session)
    db_session.commit()

    yield kwargs

    kwargs['did_type'] = kwargs['type']
    del kwargs['type']
    del kwargs['account']
    kwargs['purge_replicas'] = True
    delete_dids(dids=[kwargs], account=account)
    db_session.commit()


@pytest.fixture
def mock_request(db_session, vo, source_rse, dest_rse, file):
    account = InternalAccount('root', vo=vo)

    def teardown(req):
        delete_replicas(rse_id=source_rse['id'], files=[file], session=req.db_session)

    add_replicas(rse_id=source_rse['id'], files=[file], account=account, session=db_session)
    with GeneratedRequest(
        scope=file['scope'],
        name=file['name'],
        dest_rse_id=dest_rse['id'],
        account=account,
        db_session=db_session,
        teardown_func=teardown,
    ) as rucio_request:
        yield rucio_request.db_object


@pytest.fixture
def mock_request_no_source(db_session, dest_rse, dataset):
    with GeneratedRequest(
        scope=dataset['scope'],
        name=dataset['name'],
        dest_rse_id=dest_rse['id'],
        account=dataset['account'],
        db_session=db_session,
    ) as rucio_request:
        yield rucio_request.db_object


@pytest.fixture
def dest_throttler(db_session, mock_request):
    rucio_config.set('throttler', 'mode', 'DEST_PER_ACT', session=db_session)
    set_rse_transfer_limits(
        mock_request.dest_rse_id,
        activity=mock_request.activity,
        max_transfers=1,
        strategy='fifo',
        session=db_session,
    )
    db_session.commit()

    yield

    db_session.query(models.RSETransferLimit).filter_by(rse_id=mock_request.dest_rse_id).delete()
    rucio_config.remove_option("throttler", "mode", session=db_session)
    db_session.commit()


def test_listing_preparing_transfers(db_session, mock_request):
    req_sources = __list_transfer_requests_and_source_replicas(request_state=RequestState.PREPARING, session=db_session)

    assert len(req_sources) != 0
    found_requests = list(filter(lambda rws: rws.request_id == mock_request.id, req_sources))
    assert len(found_requests) == 1


@pytest.mark.noparallel(reason='changes global configuration value')
@pytest.mark.usefixtures("dest_throttler")
def test_preparer_setting_request_state_waiting(db_session, mock_request):
    preparer.run_once(session=db_session, logger=print)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.WAITING


def test_preparer_setting_request_state_queued(db_session, mock_request):
    preparer.run_once(session=db_session, logger=print)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED


def test_preparer_setting_request_source(db_session, vo, source_rse, mock_request):
    preparer.run_once(session=db_session, logger=print)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.QUEUED
    assert updated_mock_request.source_rse_id == source_rse['id']


def test_preparer_for_request_without_source(db_session, mock_request_no_source):
    preparer.run_once(session=db_session, logger=print)
    db_session.commit()

    updated_mock_request: "models.Request" = (
        db_session.query(models.Request).filter_by(id=mock_request_no_source.id).one()
    )

    assert updated_mock_request.state == RequestState.NO_SOURCES


def test_preparer_for_request_without_matching_transfertool_source(db_session, source_rse, dest_rse, mock_request):
    add_rse_attribute(source_rse['id'], 'transfertool', 'fts3', session=db_session)
    add_rse_attribute(dest_rse['id'], 'transfertool', 'globus', session=db_session)
    db_session.commit()

    from rucio.core.rse import REGION

    REGION.invalidate()

    preparer.run_once(session=db_session, logger=print)
    db_session.commit()

    updated_mock_request = db_session.query(models.Request).filter_by(id=mock_request.id).one()  # type: models.Request

    assert updated_mock_request.state == RequestState.NO_SOURCES


@pytest.mark.xfail(reason='fails when run in parallel')
def test_two_sources_one_destination(db_session, vo, file, mock_request):
    def setup(rse):
        add_distance(rse.rse_id, mock_request.dest_rse_id, ranking=2, session=rse.db_session)
        add_replicas(rse_id=rse.rse_id, files=[file], account=mock_request.account, session=rse.db_session)

    with GeneratedRSE(vo=vo, db_session=db_session, setup_func=setup) as source2_rse:
        src1_distance, src2_distance = (
            get_distances(
                src_rse_id=src_rse,
                dest_rse_id=mock_request.dest_rse_id,
                session=db_session,
            )
            for src_rse in (mock_request.source_rse_id, source2_rse.rse_id)
        )

        assert src1_distance and len(src1_distance) == 1 and src1_distance[0]['ranking'] == 5
        assert src2_distance and len(src2_distance) == 1 and src2_distance[0]['ranking'] == 2

        preparer.run_once(session=db_session, logger=print)
        db_session.commit()

        updated_mock_request = (
            db_session.query(models.Request).filter_by(id=mock_request.id).one()
        )  # type: models.Request

        assert updated_mock_request.state == RequestState.QUEUED
        assert updated_mock_request.source_rse_id == source2_rse.rse_id  # distance 2 < 5

        delete_replicas(rse_id=source2_rse.rse_id, files=[file], session=db_session)


def test_sort_requests_minimum_distance():
    request_dicts = [{}, {}, {}]
    for i in range(len(request_dicts)):
        request_dicts[i]['request_id'] = i
        request_dicts[i]['distance_ranking'] = 3 - i

    result = sort_requests_minimum_distance(request_dicts)
    assert next(result)['request_id'] == 2
    assert next(result)['request_id'] == 1
    assert next(result)['request_id'] == 0
    pytest.raises(StopIteration, next, result)


def test_filter_requests_for_transfertools():
    request_dicts = [{}, {}, {}]
    for i in range(len(request_dicts)):
        request_dicts[i]['request_id'] = 0  # same request for all
        request_dicts[i]['dest_rse_id'] = 'rse1'
        request_dicts[i]['src_rse_id'] = f'rse{2 + i}'

    def get_transfertools(rse_id: str) -> "Set[str]":
        assert rse_id
        if rse_id == 'rse1':
            return {'globus'}
        elif rse_id == 'rse2':
            return {'fts3'}
        elif rse_id == 'rse3':
            return {'globus'}
        elif rse_id == 'rse4':
            return {'fts3', 'globus'}
        else:
            raise AssertionError('rse_id out of range')

    transfertool_filter = get_transfertool_filter(get_transfertools=get_transfertools)
    result = list(transfertool_filter(request_dicts))
    print(result)

    assert len(result) == 2
    result.sort(key=lambda rws_dict: rws_dict['src_rse_id'])
    assert result[0]['request_id'] == 0
    assert result[0]['src_rse_id'] == 'rse3'
    assert result[0]['dest_rse_id'] == 'rse1'
    assert 'transfertool' in result[0]
    assert result[0]['transfertool'] == 'globus'
    assert result[1]['request_id'] == 0
    assert result[1]['src_rse_id'] == 'rse4'
    assert result[1]['dest_rse_id'] == 'rse1'
    assert 'transfertool' in result[1]
    assert result[1]['transfertool'] == 'globus'


def test_get_supported_transfertools_default(vo, db_session):
    with GeneratedRSE(vo=vo, db_session=db_session) as generated_rse:
        transfertools = get_supported_transfertools(rse_id=generated_rse.rse_id, session=db_session)

    assert len(transfertools) == 2
    assert 'fts3' in transfertools
    assert 'globus' in transfertools
