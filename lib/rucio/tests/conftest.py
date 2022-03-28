# -*- coding: utf-8 -*-
# Copyright 2020-2022 CERN
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
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022
# - Mayank Sharma <imptodefeat@gmail.com>, 2021-2022
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021
# - Rakshita Varadarajan <rakshitajps@gmail.com>, 2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2021

from __future__ import print_function

import traceback

import pytest


# local imports in the fixtures to make this file loadable in e.g. client tests


@pytest.fixture(scope='session')
def vo():
    from rucio.tests.common_server import get_vo
    return get_vo()


@pytest.fixture(scope='session')
def second_vo():
    from rucio.common.config import config_get_bool
    from rucio.core.vo import vo_exists, add_vo
    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        pytest.skip('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode would result in failures.')

    new_vo = 'new'
    if not vo_exists(vo=new_vo):
        add_vo(vo=new_vo, description='Test', email='rucio@email.com')
    return new_vo


@pytest.fixture(scope='session')
def long_vo():
    from rucio.tests.common import get_long_vo
    return get_long_vo()


@pytest.fixture(scope='module')
def replica_client():
    from rucio.client.replicaclient import ReplicaClient

    return ReplicaClient()


@pytest.fixture(scope='module')
def rucio_client():
    from rucio.client import Client
    return Client()


@pytest.fixture(scope='module')
def did_client():
    from rucio.client.didclient import DIDClient

    return DIDClient()


@pytest.fixture
def rest_client():
    from rucio.tests.common import print_response

    from flask.testing import FlaskClient
    from rucio.web.rest.flaskapi.v1.main import application

    class WrappedFlaskClient(FlaskClient):
        def __init__(self, *args, **kwargs):
            super(WrappedFlaskClient, self).__init__(*args, **kwargs)

        def open(self, path='/', *args, **kwargs):
            print(kwargs.get('method', 'GET'), path)
            response = super(WrappedFlaskClient, self).open(path, *args, **kwargs)
            try:
                print_response(response)
            except Exception:
                traceback.print_exc()
            return response

    _testing = application.testing
    application.testing = True
    application.test_client_class = WrappedFlaskClient
    with application.test_client() as client:
        yield client
    application.test_client_class = None
    application.testing = _testing


@pytest.fixture
def auth_token(rest_client, long_vo):
    from rucio.tests.common import vohdr, headers, loginhdr

    auth_response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))
    assert auth_response.status_code == 200
    token = auth_response.headers.get('X-Rucio-Auth-Token')
    assert token
    return str(token)


@pytest.fixture(scope='module')
def mock_scope(vo):
    from rucio.common.types import InternalScope

    return InternalScope('mock', vo=vo)


@pytest.fixture(scope='module')
def test_scope(vo):
    from rucio.common.types import InternalScope

    return InternalScope('test', vo=vo)


@pytest.fixture(scope='module')
def root_account(vo):
    from rucio.common.types import InternalAccount

    return InternalAccount('root', vo=vo)


@pytest.fixture(scope='module')
def jdoe_account(vo):
    from rucio.common.types import InternalAccount

    return InternalAccount('jdoe', vo=vo)


@pytest.fixture(scope="module")
def containerized_rses(rucio_client):
    """
    Detects if containerized rses for xrootd & ssh are available in the testing environment.
    :return: A list of (rse_name, rse_id) tuples.
    """
    from rucio.common.exception import InvalidRSEExpression

    rses = []
    try:
        xrd_rses = [x['rse'] for x in rucio_client.list_rses(rse_expression='test_container_xrd=True')]
        xrd_rses = [rucio_client.get_rse(rse) for rse in xrd_rses]
        xrd_containerized_rses = [(rse_obj['rse'], rse_obj['id']) for rse_obj in xrd_rses if "xrd" in rse_obj['rse'].lower()]
        xrd_containerized_rses.sort()
        rses.extend(xrd_containerized_rses)
        ssh_rses = [x['rse'] for x in rucio_client.list_rses(rse_expression='test_container_ssh=True')]
        ssh_rses = [rucio_client.get_rse(rse) for rse in ssh_rses]
        ssh_containerized_rses = [(rse_obj['rse'], rse_obj['id']) for rse_obj in ssh_rses if "ssh" in rse_obj['rse'].lower()]
        ssh_containerized_rses.sort()
        rses.extend(ssh_containerized_rses)
    except InvalidRSEExpression as invalid_rse_expression:
        print("{ex}. Note that containerized RSEs will not be available in non-containerized test environments"
              .format(ex=invalid_rse_expression))
        traceback.print_exc()
    return rses


@pytest.fixture
def rse_factory(vo):
    from rucio.tests.temp_factories import TemporaryRSEFactory

    with TemporaryRSEFactory(vo=vo) as factory:
        yield factory


@pytest.fixture(scope="class")
def rse_factory_unittest(request, vo):
    """
    unittest classes can get access to rse_factory fixture via this fixture
    """
    from rucio.tests.temp_factories import TemporaryRSEFactory
    with TemporaryRSEFactory(vo=vo) as factory:
        request.cls.rse_factory = factory
        yield factory
        factory.cleanup()


@pytest.fixture
def did_factory(vo, mock_scope):
    from rucio.tests.temp_factories import TemporaryDidFactory

    with TemporaryDidFactory(vo=vo, default_scope=mock_scope) as factory:
        yield factory


@pytest.fixture
def file_factory(tmp_path_factory):
    from rucio.tests.temp_factories import TemporaryFileFactory

    with TemporaryFileFactory(pytest_path_factory=tmp_path_factory) as factory:
        yield factory


@pytest.fixture
def scope_factory():
    from rucio.common.utils import generate_uuid
    from rucio.core.scope import add_scope
    from rucio.common.types import InternalAccount, InternalScope

    def create_scopes(vos, account_name=None):
        scope_uuid = str(generate_uuid()).lower()[:16]
        scope_name = 'shr_%s' % scope_uuid
        created_scopes = []
        for vo in vos:
            scope = InternalScope(scope_name, vo=vo)
            add_scope(scope, InternalAccount(account_name if account_name else 'root', vo=vo))
            created_scopes.append(scope)
        return scope_name, created_scopes

    return create_scopes


@pytest.fixture
def db_session():
    from rucio.db.sqla import session

    db_session = session.get_session()
    yield db_session
    db_session.commit()
    db_session.close()


def __get_fixture_param(request):
    fixture_param = getattr(request, "param", None)
    if not fixture_param:
        # Parametrize support is incomplete for legacy unittest test cases
        # Manually retrieve the parameters from the list of marks:
        mark = next(iter(filter(lambda m: m.name == 'parametrize', request.instance.pytestmark)), None)
        if mark:
            fixture_param = mark.args[1][0]
    return fixture_param


@pytest.fixture
def core_config_mock(request):
    """
    Fixture to allow having per-test core.config tables without affecting the other parallel tests.

    This override works only in tests which use core function calls directly, not in the ones working
    via the API, because the normal config table is not touched and the rucio instance answering API
    calls is not aware of this mock.

    This fixture acts by creating a new copy of the "config" sql table using the :memory: sqlite engine.
    Accesses to the "models.Config" table are then redirected to this temporary table via mock.patch().
    """
    from unittest import mock
    from rucio.common.utils import generate_uuid
    from sqlalchemy.pool import StaticPool
    from rucio.db.sqla.models import ModelBase, BASE, Column, String, PrimaryKeyConstraint
    from rucio.db.sqla.session import get_session, get_maker, get_engine, create_engine, declarative_base

    # Get the fixture parameters
    table_content = []
    params = __get_fixture_param(request)
    if params:
        table_content = params.get("table_content", table_content)

    # Create an in-memory dropdown replacement table for the "models.Config" table
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    InMemoryBase = declarative_base(bind=engine)

    class InMemoryConfig(InMemoryBase, ModelBase):
        __tablename__ = 'configs_' + generate_uuid()
        section = Column(String(128))
        opt = Column(String(128))
        value = Column(String(4000))
        _table_args = (PrimaryKeyConstraint('section', 'opt', name='CONFIGS_PK'), )

    InMemoryBase.metadata.create_all()

    # Register the new table with the associated engine into the sqlalchemy sessionmaker
    # In theory, this code must be protected by rucio.db.scla.session._LOCK, but this code will be executed
    # during test case initialization, so there is no risk here to have concurrent calls from within the
    # same process
    current_engine = get_engine()
    get_maker().configure(binds={BASE: current_engine, InMemoryBase: engine})

    # Fill the table with the requested mock data
    session = get_session()()
    for section, option, value in (table_content or []):
        InMemoryConfig(section=section, opt=option, value=value).save(flush=True, session=session)
    session.commit()

    with mock.patch('rucio.core.config.models.Config', new=InMemoryConfig):
        yield


@pytest.fixture
def file_config_mock(request):
    """
    Fixture which allows to have an isolated in-memory configuration file instance which
    is not persisted after exiting the fixture.

    This override works only in tests which use config calls directly, not in the ones working
    via the API, as the server config is not changed.
    """
    from unittest import mock
    from rucio.common.config import Config, config_set, config_has_section, config_add_section

    # Get the fixture parameters
    overrides = []
    params = __get_fixture_param(request)
    if params:
        overrides = params.get("overrides", overrides)

    parser = Config().parser
    with mock.patch('rucio.common.config.get_config', side_effect=lambda: parser):
        for section, option, value in (overrides or []):
            if not config_has_section(section):
                config_add_section(section)
            config_set(section, option, value)
        yield


@pytest.fixture
def caches_mock(request):
    """
    Fixture which overrides the different internal caches with in-memory ones for the duration
    of a particular test.

    This override works only in tests which use core function calls directly, not in the ones
    working via API.

    The fixture acts by by mock.patch the REGION object in the provided list of modules to mock.
    """

    from unittest import mock
    from contextlib import ExitStack
    from dogpile.cache import make_region

    caches_to_mock = []
    params = __get_fixture_param(request)
    if params:
        caches_to_mock = params.get("caches_to_mock", caches_to_mock)

    with ExitStack() as stack:
        mocked_caches = []
        for module in caches_to_mock:
            region = make_region().configure('dogpile.cache.memory', expiration_time=600)
            stack.enter_context(mock.patch(module, new=region))
            mocked_caches.append(region)

        yield mocked_caches


@pytest.fixture
def metrics_mock():
    """
    Overrides the prometheus metric registry and allows to verify if the desired
    prometheus metrics were correctly recorded.
    """

    from unittest import mock
    from prometheus_client import CollectorRegistry, values

    with mock.patch('rucio.core.monitor.REGISTRY', new=CollectorRegistry()) as registry, \
            mock.patch('rucio.core.monitor.COUNTERS', new={}), \
            mock.patch('rucio.core.monitor.GAUGES', new={}), \
            mock.patch('rucio.core.monitor.TIMINGS', new={}), \
            mock.patch('prometheus_client.values.ValueClass', new=values.MutexValue):
        yield registry
