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

import pytest

from rucio.common.exception import CannotAuthenticate, ClientProtocolNotFound, ClientProtocolNotSupported, MissingClientParameter, RucioException
from rucio.common.utils import execute
from rucio.tests.common import remove_config, skip_outside_gh_actions
from tests.mocks.mock_http_server import MockServer


@pytest.fixture
def client_token_path_override(file_config_mock, function_scope_prefix, tmp_path):
    """
    Ensure each running client has a different path for the token, otherwise tests cannot run in parallel
    """
    from rucio.common.config import config_set
    config_set('client', 'auth_token_file_path', str(tmp_path / f'{function_scope_prefix}token'))


@pytest.mark.usefixtures("client_token_path_override")
class TestBaseClient:
    """ To test Clients"""

    from rucio.common.config import config_get

    cacert = config_get('test', 'cacert')
    usercert = config_get('test', 'usercert')
    userkey = config_get('test', 'userkey')

    def test_userpass(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with userpass."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient
        client = BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, vo=vo)
        print(client)

    def test_userpass_wrong_creds(self, vo):
        """ CLIENTS (BASECLIENT): try to authenticate with wrong username."""
        creds = {'username': 'wrong', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, vo=vo)

    def test_userpass_no_ca_cert(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with userpass without ca cert."""
        creds = {'username': 'wrong', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_userpass_no_creds_passed(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with userpass, with no credentials passed"""
        from rucio.client.baseclient import BaseClient

        client = BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=None, vo=vo)
        assert client.creds['username'] == 'ddmlab'
        assert client.creds['password'] == 'secret'

    @skip_outside_gh_actions
    def test_x509(self, vo):
        """ CLIENTS (BASECLIENT): authenticate with x509."""
        from rucio.client.baseclient import BaseClient

        creds = {'client_cert': self.usercert,
                 'client_key': self.userkey}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, vo=vo)

    @pytest.mark.parametrize("cert_path", ["", '/opt/rucio/etc/web/notthere.crt'])
    def test_x509_non_existing_cert(self, vo, cert_path):
        """ CLIENTS (BASECLIENT): authenticate with x509 with missing certificate."""
        creds = {'client_cert': cert_path}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(MissingClientParameter, match=rf"X\.509 client certificate not found: '{cert_path}'"):
            BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, vo=vo)

    def test_client_rucio_protocol_not_supported(self, vo):
        """ CLIENTS (BASECLIENT): try to pass a rucio host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(ClientProtocolNotSupported):
            BaseClient(rucio_host='junk://localhost', auth_host='http://localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_client_auth_protocol_not_supported(self, vo):
        """ CLIENTS (BASECLIENT): try to pass an auth host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(ClientProtocolNotSupported):
            BaseClient(rucio_host='https://localhost', auth_host='junk://localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_client_rucio_and_auth_protocol_not_supported(self, vo):
        """ CLIENTS (BASECLIENT): try to pass both a rucio and auth host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(ClientProtocolNotSupported):
            BaseClient(rucio_host='junk://localhost', auth_host='junk://localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_client_rucio_protocol_not_found(self, vo):
        """ CLIENTS (BASECLIENT): try to pass a rucio host with a missing protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(ClientProtocolNotFound):
            BaseClient(rucio_host='localhost', auth_host='https://localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_client_auth_protocol_not_found(self, vo):
        """ CLIENTS (BASECLIENT): try to pass an auth host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(ClientProtocolNotFound):
            BaseClient(rucio_host='http://localhost', auth_host='localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_client_rucio_and_auth_protocol_not_found(self, vo):
        """ CLIENTS (BASECLIENT): try to pass both a rucio and auth host with a missing protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client.baseclient import BaseClient

        with pytest.raises(ClientProtocolNotFound):
            BaseClient(rucio_host='localhost', auth_host='localhost', account='root', auth_type='userpass', creds=creds, vo=vo)

    def test_retry_on_502_always_fail(self, vo):
        """ CLIENTS (BASECLIENT): Ensure client retries on 502 error codes, but fails on repeated errors"""
        from rucio.client.baseclient import BaseClient

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

    def test_retry_on_502_succeeds_eventually(self, vo):
        """ CLIENTS (BASECLIENT): Ensure client retries on 502 error codes"""
        invocations = []
        from rucio.client.baseclient import BaseClient

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

    marker = '$> '

    def test_ping(self, vo):
        """ PING (CLIENT): Ping Rucio """

        creds = {'username': 'ddmlab', 'password': 'secret'}

        from rucio.client.client import Client
        from rucio.common.config import config_get

        cacert = config_get('test', 'cacert')
        client = Client(account='root', ca_cert=cacert, auth_type='userpass', creds=creds, vo=vo)
        print(client.ping())

    @pytest.mark.noparallel(reason='We temporarily remove the config file.')
    @remove_config
    def test_import_without_config_file(self, vo):
        """
        The Client should be importable without a config file, since it is
        configurable afterwards.

        We are in a fully configured environment with a default config file. We
        thus have to disable the access to it (move it) and make sure to run the
        code in a different environment.
        """

        exitcode, _, err = execute("python -c 'from rucio.client import Client'")
        print(exitcode, err)
        assert exitcode == 0
        assert "Could not load Rucio configuration file." not in err

    @pytest.mark.noparallel(reason='We temporarily remove the config file.')
    @remove_config
    def test_run_client_no_config(self, vo):
        rucio_host = "https://rucio:443"
        auth_host = "https://rucio:443"
        ca_cert = "/etc/grid-security/certificates/5fca1cb1.0"
        creds = {'username': 'ddmlab', 'password': 'secret'}

        from rucio.client.client import Client

        client = Client(
            rucio_host=rucio_host,
            auth_host=auth_host,
            ca_cert=ca_cert,
            account='root',
            auth_type='userpass',
            creds=creds,
            vo=vo)

        # Couple of basic calls
        # account
        assert client.whoami()['account'] == 'root'
        assert client.get_account('jdoe')['account'] == "jdoe"

        # config
        assert client.set_config_option("mock_section", "mock_option", value=0)

        # did
        assert list(client.list_dids(scope='mock', filters={})) is not None

        # replica
        assert list(client.list_replicas(dids=[])) is not None

        # rse
        assert list(client.list_rses()) is not None

        # rule
        assert list(client.list_replication_rules()) is not None
