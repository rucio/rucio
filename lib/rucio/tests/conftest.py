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
def file_factory(vo, mock_scope):
    from rucio.tests.temp_factories import TemporaryFileFactory

    with TemporaryFileFactory(vo=vo, default_scope=mock_scope) as factory:
        yield factory
