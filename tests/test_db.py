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

from unittest.mock import patch

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import TimeoutError as SQLATimeoutError

from rucio.common.exception import DatabaseException, InputValidationError
from rucio.common.utils import generate_uuid
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import NullPool, QueuePool, SingletonThreadPool, _get_engine_poolclass, db_session, get_session


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
    from rucio.common.exception import DatabaseException
    from rucio.web.rest.flaskapi.v1.ping import Ping

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


def _config_rows(section, session):
    """ Returns the (opt, value) pairs stored in the config table for the given section. """
    stmt = select(
        models.Config.opt,
        models.Config.value
    ).where(
        models.Config.section == section
    )
    return [tuple(row) for row in session.execute(stmt)]


@pytest.mark.noparallel(reason='Uses the config table, which reset_config_table clears.')
class TestDbSession:

    @pytest.fixture
    def section(self):
        """ A unique config section for one test; its rows are removed afterwards. """
        section = f'test_db_session_{generate_uuid()[:8]}'
        yield section
        with db_session(DatabaseOperationType.WRITE) as session:
            stmt = delete(
                models.Config
            ).where(
                models.Config.section == section
            )
            session.execute(stmt)

    def test_write_commits_on_success(self, section):
        """ DB (CORE): db_session WRITE commits on success """
        with db_session(DatabaseOperationType.WRITE) as session:
            models.Config(section=section, opt='committed', value='yes').save(session=session)

        with db_session(DatabaseOperationType.READ) as session:
            assert _config_rows(section, session) == [('committed', 'yes')]

    def test_write_rolls_back_and_reraises_on_error(self, section):
        """ DB (CORE): db_session WRITE rolls back and re-raises on error """
        with pytest.raises(RuntimeError, match='abort'):
            with db_session(DatabaseOperationType.WRITE) as session:
                models.Config(section=section, opt='rolled_back', value='no').save(session=session)
                raise RuntimeError('abort')

        with db_session(DatabaseOperationType.READ) as session:
            assert _config_rows(section, session) == []

    def test_read_never_commits(self, section):
        """ DB (CORE): db_session READ never commits """
        with db_session(DatabaseOperationType.READ) as session:
            models.Config(section=section, opt='not_committed', value='no').save(session=session)

        with db_session(DatabaseOperationType.READ) as session:
            assert _config_rows(section, session) == []

    def test_database_error_becomes_database_exception(self, section):
        """ DB (CORE): db_session turns a failing statement into DatabaseException and rolls back """
        with pytest.raises(DatabaseException):
            with db_session(DatabaseOperationType.WRITE) as session:
                models.Config(section=section, opt='failed', value='no').save(session=session)
                session.execute(text('SELECT 1 FROM table_that_does_not_exist'))

        with db_session(DatabaseOperationType.READ) as session:
            assert _config_rows(section, session) == []

    def test_timeout_error_becomes_database_exception(self, section):
        """ DB (CORE): db_session turns a pool TimeoutError into DatabaseException and rolls back """
        with pytest.raises(DatabaseException):
            with db_session(DatabaseOperationType.WRITE) as session:
                models.Config(section=section, opt='timed_out', value='no').save(session=session)
                raise SQLATimeoutError('pool timeout')

        with db_session(DatabaseOperationType.READ) as session:
            assert _config_rows(section, session) == []
