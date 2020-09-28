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
    backend = os.environ.get('REST_BACKEND', 'flask')
    if backend == 'flask':
        from flask.testing import FlaskClient as WebClient
    elif backend == 'webpy':
        from werkzeug.test import Client as WebClient
    else:
        raise RuntimeError('Unknown rest backend ' + backend)

    from rucio.tests.common import print_response

    class WrappedTestClient(WebClient):
        def __init__(self, *args, **kwargs):
            super(WrappedTestClient, self).__init__(*args, **kwargs)

        def open(self, *args, **kwargs):
            response = super(WrappedTestClient, self).open(*args, **kwargs)
            try:
                print_response(response)
            except Exception:
                traceback.print_exc()
            return response

    if backend == 'flask':
        from rucio.web.rest.flaskapi.v1.main import application

        _testing = application.testing
        application.testing = True
        application.test_client_class = WrappedTestClient
        with application.test_client() as client:
            yield client
        application.test_client_class = None
        application.testing = _testing
    elif backend == 'webpy':
        from werkzeug.wrappers import BaseResponse
        from rucio.web.rest.webpy.v1.main import application

        yield WrappedTestClient(application, BaseResponse)


@pytest.fixture
def auth_token(rest_client, vo):
    from rucio.tests.common import vohdr, headers, loginhdr

    auth_response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(vo)))
    assert auth_response.status_code == 200
    token = auth_response.headers.get('X-Rucio-Auth-Token')
    assert token
    return str(token)
