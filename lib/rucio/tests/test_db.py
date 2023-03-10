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
from unittest.mock import patch

from sqlalchemy import text
from rucio.db.sqla.session import get_session, _get_engine_poolclass, NullPool, QueuePool, SingletonThreadPool
from rucio.common.exception import InputValidationError


def test_db_connection():
    """ DB (CORE): Test db connection """
    session = get_session()
    if session.bind.dialect.name == 'oracle':
        session.execute(text('select 1 from dual'))
    else:
        session.execute(text('select 1'))
    session.close()


def test_config_poolclass():
    assert _get_engine_poolclass('nullpool') is NullPool
    assert _get_engine_poolclass('queuepool') is QueuePool
    assert _get_engine_poolclass('singletonthreadpool') is SingletonThreadPool

    with pytest.raises(InputValidationError, match='Unknown poolclass: unknown'):
        _get_engine_poolclass('unknown')


@pytest.mark.noparallel(reason='Changes an internal method of MethodView.')
def test_pooloverload():
    """ DB (WEB): Test response to a DatabaseException due to Pool Overflow """
    from rucio.web.rest.flaskapi.v1.ping import Ping
    from rucio.common.exception import DatabaseException

    # Create a new ErrorHandlingMethodView as_view
    ping_view = Ping.as_view('ping')

    # specification for the mock we create to replace flask.request
    # without specifying this, _is_async_obj is run which triggers flask RuntimeError
    class T:
        method = 'replacement string'

    patch_flask = patch('flask.request', spec=T)

    patch_getheaders = patch('rucio.web.rest.flaskapi.v1.ping.Ping.get_headers')
    patch_dispatch = patch(
        'flask.views.MethodView.dispatch_request',
        side_effect=DatabaseException("QueuePool Exception Somehow")
    )

    patch_flask.start()
    patch_getheaders.start()
    patch_dispatch.start()

    response = ping_view.view_class.dispatch_request(ping_view.view_class)
    # Assert the correct error is raised.
    assert ('Currently there are too many requests for the Rucio servers to handle. '
            'Please try again in a few minutes.' in response.data.decode())

    patch.stopall()
