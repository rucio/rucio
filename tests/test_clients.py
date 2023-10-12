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

from datetime import datetime, timedelta

from os import rename

import pytest

from rucio.client.baseclient import BaseClient
from rucio.client.client import Client
from rucio.common.config import config_get, config_set, Config
from rucio.common.exception import CannotAuthenticate, ClientProtocolNotSupported, RucioException
from rucio.common.utils import execute
from tests.mocks.mock_http_server import MockServer


@pytest.fixture
def client_token_path_override(file_config_mock, function_scope_prefix, tmp_path):
    """
    Ensure each running client has a different path for the token, otherwise tests cannot run in parallel
    """
    config_set('client', 'auth_token_file_path', str(tmp_path / f'{function_scope_prefix}token'))


@pytest.mark.usefixtures("client_token_path_override")
class TestBaseClient:
    """ To test Clients"""

    cacert = config_get('test', 'cacert')
    usercert = config_get('test', 'usercert')
    userkey = config_get('test', 'userkey')

    def testUserpass(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with userpass."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        client = BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, vo=vo)
        print(client)

    def testUserpassWrongCreds(self, vo):
        """ CLIENTS (BASECLIENT): try to authenticate with wrong username."""
        creds = {'username': 'wrong', 'password': 'secret'}
        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, vo=vo)

    def testUserpassNoCACert(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with userpass without ca cert."""
        creds = {'username': 'wrong', 'password': 'secret'}
        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', auth_type='userpass', creds=creds, vo=vo)

    def testx509(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with x509."""
        creds = {'client_cert': self.usercert,
                 'client_key': self.userkey}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, vo=vo)

    def testx509NonExistingCert(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with x509 with missing certificate."""
        creds = {'client_cert': '/opt/rucio/etc/web/notthere.crt'}
        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, vo=vo)

    def testClientProtocolNotSupported(self, vo):
        """ CLIENTS (BASECLIENT): try to pass an host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        with pytest.raises(ClientProtocolNotSupported):
            BaseClient(rucio_host='localhost', auth_host='junk://localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def testRetryOn502AlwaysFail(self, vo):
        """ CLIENTS (BASECLIENT): Ensure client retries on 502 error codes, but fails on repeated errors"""

        class AlwaysFailWith502(MockServer.Handler):
            def do_GET(self):
                self.send_code_and_message(502, {}, '')

        with MockServer(AlwaysFailWith502) as server:
            with pytest.raises(CannotAuthenticate):
                creds = {'username': 'ddmlab', 'password': 'secret'}
                BaseClient(rucio_host=server.base_url, auth_host=server.base_url, account='root', auth_type='userpass', creds=creds, vo=vo)
            with pytest.raises(RucioException):
                creds = {'client_cert': self.usercert,
                         'client_key': self.userkey}
                BaseClient(rucio_host=server.base_url, auth_host=server.base_url, account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, vo=vo)

    def testRetryOn502SucceedsEventually(self, vo):
        """ CLIENTS (BASECLIENT): Ensure client retries on 502 error codes"""
        invocations = []

        class FailTwiceWith502(MockServer.Handler):
            def do_GET(self, invocations=invocations):
                invocations.append(self.path)
                if len(invocations) <= 2:
                    self.send_code_and_message(502, {}, '')
                else:
                    self.send_code_and_message(200, {'x-rucio-auth-token': 'sometoken'}, '')

        start_time = datetime.utcnow()
        with MockServer(FailTwiceWith502) as server:
            creds = {'username': 'ddmlab', 'password': 'secret'}
            del invocations[:]
            client = BaseClient(rucio_host=server.base_url, auth_host=server.base_url, account='root', auth_type='userpass', creds=creds, vo=vo)
            del invocations[:]
            client._send_request(server.base_url)  # noqa
        # The client did back-off multiple times before succeeding: 2 * 0.25s (authentication) + 2 * 0.25s (request) = 1s
        assert datetime.utcnow() - start_time > timedelta(seconds=0.9)


class TestRucioClients:
    """ To test Clients"""

    cacert = config_get('test', 'cacert')
    marker = '$> '

    def test_ping(self, vo):
        """ PING (CLIENT): Ping Rucio """
        creds = {'username': 'ddmlab', 'password': 'secret'}

        client = Client(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, vo=vo)

        print(client.ping())

    @pytest.mark.noparallel(reason='We temporarily remove the config file.')
    def test_import_without_config_file(self, vo):
        """
        The Client should be importable without a config file, since it is
        configurable afterwards.

        We are in a fully configured environment with a default config file. We
        thus have to disable the access to it (move it) and make sure to run the
        code in a different environment.
        """
        configfile = Config().configfile
        rename(configfile, f"{configfile}.tmp")
        try:
            exitcode, _, err = execute("python -c 'from rucio.client import Client'")
            print(exitcode, err)
            assert exitcode == 0
            assert "RuntimeError: Could not load Rucio configuration file." not in err
        finally:
            # This is utterly important to not mess up the environment.
            rename(f"{configfile}.tmp", configfile)
