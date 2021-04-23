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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from __future__ import print_function

import importlib
import os
import traceback

import pytest


# local imports in the fixtures to make this file loadable in e.g. client tests


@pytest.fixture(scope='session')
def vo():
    from rucio.common.config import config_get_bool, config_get

    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        return config_get('client', 'vo', raise_exception=False, default='tst')
    else:
        return 'def'


@pytest.fixture(scope='module')
def replica_client():
    from rucio.client.replicaclient import ReplicaClient

    return ReplicaClient()


@pytest.fixture(scope='module')
def did_client():
    from rucio.client.didclient import DIDClient

    return DIDClient()


@pytest.fixture
def rest_client():
    from rucio.tests.common import print_response

    backend = os.environ.get('REST_BACKEND', 'webpy')
    if backend == 'flask':
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
    elif backend == 'webpy':
        from werkzeug.test import Client as TestClient
        from werkzeug.wrappers import BaseResponse
        from rucio.web.rest.main import application as main_application

        def _path_matches_endpoint(path, endpoint):
            return path.startswith(endpoint + '/') or path.startswith(endpoint + '?') or path == endpoint

        class WrappedTestClient(TestClient):
            special_endpoints = {
                '/auth': ('rucio.web.rest.authentication', None),
                '/credentials': ('rucio.web.rest.credential', None),
                '/nongrid_traces': ('rucio.web.rest.nongrid_trace', None),
                '/ping': ('rucio.web.rest.ping', None),
                '/redirect': ('rucio.web.rest.redirect', None),
                '/traces': ('rucio.web.rest.trace', None),
            }

            def __init__(self, *args, **kwargs):
                super(WrappedTestClient, self).__init__(*args, **kwargs)

            def _endpoint_specials(self, path):
                for endpoint_path in self.special_endpoints:
                    if _path_matches_endpoint(path, endpoint_path):
                        endpoint_module, endpoint_client = self.special_endpoints[endpoint_path]
                        if endpoint_client is None:
                            module = importlib.import_module(endpoint_module)
                            endpoint_client = TestClient(getattr(module, 'application'), BaseResponse)
                            self.special_endpoints[endpoint_path] = (module, endpoint_client)

                        path = path[len(endpoint_path):]
                        if not path.startswith('/'):
                            path = '/' + path

                        return path, endpoint_client.open
                return path, super(WrappedTestClient, self).open

            def open(self, path='/', *args, **kwargs):
                newpath, open_method = self._endpoint_specials(path)
                print(kwargs.get('method', 'GET'), path)
                response = open_method(newpath, *args, **kwargs)
                try:
                    print_response(response)
                except Exception:
                    traceback.print_exc()
                return response

        yield WrappedTestClient(main_application, BaseResponse)
    else:
        raise RuntimeError('Unknown rest backend ' + backend)


@pytest.fixture
def auth_token(rest_client, vo):
    from rucio.tests.common import vohdr, headers, loginhdr

    auth_response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(vo)))
    assert auth_response.status_code == 200
    token = auth_response.headers.get('X-Rucio-Auth-Token')
    assert token
    return str(token)


@pytest.fixture(scope='module')
def mock_scope(vo):
    from rucio.common.types import InternalScope

    return InternalScope('mock', vo=vo)


@pytest.fixture(scope='module')
def root_account(vo):
    from rucio.common.types import InternalAccount

    return InternalAccount('root', vo=vo)


@pytest.fixture
def rse_factory(vo):
    from rucio.tests.temp_factories import TemporaryRSEFactory

    with TemporaryRSEFactory(vo=vo) as factory:
        yield factory


@pytest.fixture
def did_factory(vo, mock_scope):
    from rucio.tests.temp_factories import TemporaryDidFactory

    with TemporaryDidFactory(vo=vo, default_scope=mock_scope) as factory:
        yield factory


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
        for module in caches_to_mock:
            region = make_region().configure('dogpile.cache.memory', expiration_time=600)
            stack.enter_context(mock.patch('{}.{}'.format(module, 'REGION'), new=region))

        yield
