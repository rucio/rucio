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

from rucio.client.baseclient import BaseClient
from rucio.common.config import config_set
from rucio.common.exception import CannotAuthenticate, NoAuthInformation
from tests.mocks.mock_http_server import MockServer


@pytest.fixture
def client_token_path_override(file_config_mock, function_scope_prefix, tmp_path):
    """
    Ensure each running client has a different path for the token, otherwise tests cannot run in parallel
    """
    config_set('client', 'auth_token_file_path', str(tmp_path / f'{function_scope_prefix}token'))

class TestOIDCAuthentication:
    """
    Tests for OIDC authentication flow in BaseClient using mock HTTP server.
    
    Rationale for keeping these tests:
    - Unit Testing Focus: Test specific BaseClient OIDC authentication logic in isolation
    - Branch Coverage: Verify all code paths (auto, polling, manual) are exercised
    - Error Handling: Test edge cases and failure scenarios with controlled mock responses
    - Fast Execution: Mock server provides immediate responses without external dependencies
    - Deterministic Testing: Predictable behavior for CI/CD pipelines and parallel test execution
    - Integration Complement: These unit tests complement external Keycloak integration tests
    
    These tests answer: "Does BaseClient's OIDC authentication logic work correctly?"
    They complement external integration tests which answer: "Does the system work with real services?"
    """

    @staticmethod
    def safe_reduce_data(self, data, maxlen: int = 132) -> str:
        """Safe _reduce_data implementation that handles dictionaries"""
        if isinstance(data, dict):
            data_str = str(data)
            if len(data_str) > maxlen:
                return f"{data_str[:maxlen-15]} ... {data_str[-10:]}"
            return data_str
        # Original logic for str/bytes
        text = data if isinstance(data, str) else data.decode("utf-8")
        if len(text) > maxlen:
            text = "%s ... %s" % (text[:maxlen - 15], text[-10:])
        return text

    @staticmethod
    def get_server_url(server_address, path="/auth/login"):
        """Helper to build server URL from address"""
        if isinstance(server_address, tuple) and len(server_address) >= 2:
            server_name, server_port = server_address[:2]
            return f'http://{server_name}:{server_port}{path}'
        return f'http://localhost:0{path}'

    def create_base_client(self, server, creds, vo, ca_cert=False):
        """Helper to create BaseClient with common patches"""
        
        with patch('rucio.client.baseclient.wlcg_token_discovery', return_value=None):
            with patch('rucio.client.baseclient.BaseClient._reduce_data', self.safe_reduce_data):
                return BaseClient(
                    rucio_host=server.base_url,
                    auth_host=server.base_url,
                    account='root',
                    ca_cert=None,
                    auth_type='oidc',
                    creds=creds,
                    vo=vo
                )

    def test_oidc_auto_authentication_success(self, vo, client_token_path_override):
        """Test successful OIDC auto authentication """
        
        class OIDCMockHandler(MockServer.Handler):
            def do_GET(self):
                if '/auth/oidc' in self.path:
                    auth_url = TestOIDCAuthentication.get_server_url(self.server.server_address)
                    self.send_code_and_message(200, {
                        'X-Rucio-OIDC-Auth-URL': auth_url
                    }, '')
                elif '/auth/login' in self.path:
                    self.send_code_and_message(200, {
                        'X-Rucio-Auth-Token': 'test-oidc-token-12345'
                    }, 'redirect_success')
                else:
                    self.send_code_and_message(404, {}, '')
            
            def do_POST(self): # noqa: N802
                if '/auth/login' in self.path:
                    self.send_code_and_message(200, {
                        'X-Rucio-Auth-Token': 'test-oidc-token-12345'
                    }, '')
                else:
                    self.send_code_and_message(404, {}, '')

        creds = {
            'oidc_auto': True,
            'oidc_username': 'testuser',
            'oidc_password': 'testpass',
            'oidc_scope': 'openid profile',
            'oidc_audience': 'rucio',
            'oidc_issuer': 'test-issuer',
            'oidc_refresh_lifetime': None,
            'oidc_polling': False
        }

        with MockServer(OIDCMockHandler) as server:
            client = self.create_base_client(server, creds, vo)
            assert client.auth_token == 'test-oidc-token-12345'

    def test_oidc_polling_authentication_success(self, vo, client_token_path_override):
        """Test successful OIDC polling authentication """
        
        poll_attempts = []
        
        class OIDCPollingMockHandler(MockServer.Handler):
            def do_GET(self):
                if '/auth/oidc' in self.path:
                    auth_url = TestOIDCAuthentication.get_server_url(self.server.server_address, '/auth/polling')
                    self.send_code_and_message(200, {
                        'X-Rucio-OIDC-Auth-URL': auth_url
                    }, '')
                elif '/auth/polling' in self.path:
                    poll_attempts.append(1)
                    if len(poll_attempts) <= 2:
                        # First two polls return no token
                        self.send_code_and_message(200, {}, '')
                    else:
                        # Third poll returns token
                        self.send_code_and_message(200, {
                            'X-Rucio-Auth-Token': 'test-polling-token-67890'
                        }, '')
                else:
                    self.send_code_and_message(404, {}, '')

        creds = {
            'oidc_auto': False,
            'oidc_polling': True,
            'oidc_scope': 'openid profile',
            'oidc_audience': 'rucio',
            'oidc_issuer': 'test-issuer',
            'oidc_refresh_lifetime': None
        }

        # Mock time.sleep to speed up test
        with patch('time.sleep'):
            with MockServer(OIDCPollingMockHandler) as server:
                client = self.create_base_client(server, creds, vo)
                assert client.auth_token == 'test-polling-token-67890'
                assert len(poll_attempts) == 3

    def test_oidc_manual_code_authentication_success(self, vo, client_token_path_override):
        """Test successful OIDC manual code authentication """
        
        class OIDCManualMockHandler(MockServer.Handler):
            def do_GET(self):
                if '/auth/oidc_redirect' in self.path:
                    if 'valid-code-123' in self.path:
                        self.send_code_and_message(200, {
                            'X-Rucio-Auth-Token': 'test-manual-token-abc'
                        }, '')
                    else:
                        self.send_code_and_message(400, {}, 'Invalid code')
                elif '/auth/oidc' in self.path:
                    auth_url = TestOIDCAuthentication.get_server_url(self.server.server_address, '/auth/manual')
                    self.send_code_and_message(200, {
                        'X-Rucio-OIDC-Auth-URL': auth_url
                    }, '')
                elif '/auth/manual' in self.path:
                    # Return the manual auth page
                    self.send_code_and_message(200, {}, 'manual_auth_page')
                else:
                    self.send_code_and_message(404, {}, '')

        creds = {
            'oidc_auto': False,
            'oidc_polling': False,
            'oidc_scope': 'openid profile',
            'oidc_audience': 'rucio',
            'oidc_issuer': 'test-issuer',
            'oidc_refresh_lifetime': None
        }

        # Mock user input for fetchcode
        with patch('builtins.input', return_value='valid-code-123'):
            with MockServer(OIDCManualMockHandler) as server:
                client = self.create_base_client(server, creds, vo)
                assert client.auth_token == 'test-manual-token-abc'

    def test_oidc_authentication_missing_auth_url(self, vo, client_token_path_override):
        """Test OIDC authentication fails without auth URL """
        
        class OIDCNoAuthUrlHandler(MockServer.Handler):
            def do_GET(self):
                if '/auth/oidc' in self.path:
                    # Don't return X-Rucio-OIDC-Auth-URL header
                    self.send_code_and_message(200, {}, '')
                else:
                    self.send_code_and_message(404, {}, '')

        creds = {
            'oidc_auto': True,
            'oidc_username': 'testuser',
            'oidc_password': 'testpass',
            'oidc_scope': 'openid profile'
        }

        with MockServer(OIDCNoAuthUrlHandler) as server:
            with pytest.raises(CannotAuthenticate):
                self.create_base_client(server, creds, vo)

    def test_oidc_authentication_oauth_error(self, vo, client_token_path_override):
        """Test OIDC authentication fails with OAuth error """
        
        class OIDCOAuthErrorHandler(MockServer.Handler):
            def do_GET(self):
                if '/auth/oidc' in self.path:
                    auth_url = TestOIDCAuthentication.get_server_url(self.server.server_address)
                    self.send_code_and_message(200, {
                        'X-Rucio-OIDC-Auth-URL': auth_url
                    }, '')
                elif '/auth/login' in self.path:
                    self.send_code_and_message(200, {}, 'OAuth Error: invalid_client')
                else:
                    self.send_code_and_message(404, {}, '')
            
            def do_POST(self): # noqa: N802
                if '/auth/login' in self.path:
                    # Return OAuth error in response body
                    self.send_code_and_message(400, {}, 'OAuth Error: invalid_client')
                else:
                    self.send_code_and_message(404, {}, '')

        creds = {
            'oidc_auto': True,
            'oidc_username': 'testuser',
            'oidc_password': 'testpass',
            'oidc_scope': 'openid profile'
        }

        with MockServer(OIDCOAuthErrorHandler) as server:
            with pytest.raises(CannotAuthenticate):
                self.create_base_client(server, creds, vo)

    def test_oidc_manual_invalid_code_retries(self, vo, client_token_path_override):
        """Test OIDC manual authentication with invalid codes and retries """
        
        class OIDCInvalidCodeHandler(MockServer.Handler):
            def do_GET(self):
                if '/auth/oidc_redirect' in self.path:
                    # Always return error for invalid codes
                    self.send_code_and_message(400, {}, 'Invalid code')
                elif '/auth/oidc' in self.path:
                    auth_url = TestOIDCAuthentication.get_server_url(self.server.server_address, '/auth/manual')
                    self.send_code_and_message(200, {
                        'X-Rucio-OIDC-Auth-URL': auth_url
                    }, '')
                else:
                    self.send_code_and_message(404, {}, '')

        creds = {
            'oidc_auto': False,
            'oidc_polling': False,
            'oidc_scope': 'openid profile'
        }

        # Mock user input to provide invalid codes 3 times
        with patch('builtins.input', side_effect=['invalid-1', 'invalid-2', 'invalid-3']):
            with MockServer(OIDCInvalidCodeHandler) as server:
                with pytest.raises(CannotAuthenticate):
                    self.create_base_client(server, creds, vo)

    def test_oidc_missing_credentials_auto(self, vo, client_token_path_override):
        """Test OIDC authentication fails with missing auto credentials """
        
        creds = {
            'oidc_auto': True,
            'oidc_username': None,  # Missing username
            'oidc_password': 'testpass',
            'oidc_scope': 'openid profile'
        }

        # This test doesn't need a server since it fails before authentication
        
        with patch('rucio.client.baseclient.wlcg_token_discovery', return_value=None):
            with pytest.raises(NoAuthInformation,
                              match='For automatic OIDC log-in with your Identity Provider username and password are required.'):
                BaseClient(
                    rucio_host='http://localhost:8080',
                    auth_host='http://localhost:8080',
                    account='root',
                    ca_cert=None,
                    auth_type='oidc',
                    creds=creds,
                    vo=vo
                )