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

from rucio.db.sqla import models
from rucio.db.sqla.session import get_session, _get_engine_poolclass, NullPool, QueuePool, SingletonThreadPool
from rucio.db.sqla.util import query_to_list_of_dicts, result_to_dict
from rucio.common.exception import InputValidationError


def test_db_connection():
    """ DB (CORE): Test db connection """
    session = get_session()
    if session.bind.dialect.name == 'oracle':
        session.execute('select 1 from dual')
    else:
        session.execute('select 1')
    session.close()


def test_config_poolclass():
    assert _get_engine_poolclass('nullpool') is NullPool
    assert _get_engine_poolclass('queuepool') is QueuePool
    assert _get_engine_poolclass('singletonthreadpool') is SingletonThreadPool

    with pytest.raises(InputValidationError, match='Unknown poolclass: unknown'):
        _get_engine_poolclass('unknown')


def test_result_to_dict_contains_all_keys(db_session, rse_factory):
    _, rse_id = rse_factory.make_mock_rse()
    rse_result = db_session.query(models.RSE).filter(models.RSE.id == rse_id).one()

    assert result_to_dict(rse_result).keys() == dict(models.RSE.__table__.columns).keys()


def test_result_to_dict(db_session, rse_factory):
    _, rse_id = rse_factory.make_mock_rse()
    rse_result = db_session.query(models.RSE).filter(models.RSE.id == rse_id).one()

    expected = {}
    for column in rse_result.__table__.columns:
        expected[column.name] = getattr(rse_result, column.name)

    assert result_to_dict(rse_result) == expected


def test_query_to_list_of_dicts_empty_result(db_session):
    query = db_session.query(models.RSE).filter(models.RSE.id.is_(None))
    assert list(query_to_list_of_dicts(query)) == list()


def test_query_to_list_of_dicts_contains_all_keys(db_session, rse_factory):
    _, rse_id = rse_factory.make_mock_rse()
    query = db_session.query(models.RSE).filter(models.RSE.id == rse_id)

    res = list(query_to_list_of_dicts(query))
    assert len(res) == 1
    assert res[0].keys() == dict(models.RSE.__table__.columns).keys()


def test_query_to_list_of_dicts(db_session, rse_factory):
    _, rse_id = rse_factory.make_mock_rse()
    query = db_session.query(models.RSE).filter(models.RSE.id == rse_id)

    expected = []
    for item in query:
        tmp = {}
        for column in item.__table__.columns:
            tmp[column.name] = getattr(item, column.name)
        expected.append(tmp)

    assert list(query_to_list_of_dicts(query)) == expected
