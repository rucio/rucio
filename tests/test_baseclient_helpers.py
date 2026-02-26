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

import os
from configparser import NoSectionError
from unittest.mock import Mock, patch

import pytest
from requests import codes

from rucio.client.baseclient import OIDC_MAX_CODE_ATTEMPTS, OIDC_POLLING_TIMEOUT_SECONDS, BaseClient
from rucio.common.exception import ClientProtocolNotFound, ClientProtocolNotSupported


class TestBaseClientHelperMethods:
    """Test the extracted helper methods from BaseClient refactoring."""

    @pytest.fixture
    def mock_config(self):
        """Mock configuration to prevent real config file reads."""
        with patch('rucio.client.baseclient.config_get') as mock:
            mock.return_value = 'https://test-rucio.cern.ch'
            yield mock

    @pytest.fixture
    def mock_client_partial(self, mock_config):
        """Create a partially initialized BaseClient for testing helpers."""
        client = object.__new__(BaseClient)
        client.logger = Mock()
        client.session = Mock()
        return client

    def test_setup_session_formats_user_agent_correctly(self):
        """Test _setup_session formats user agent with version."""
        client = object.__new__(BaseClient)
        client._setup_session('test-client')

        assert client.user_agent.startswith('test-client/')
        assert client.script_id is not None

    def test_setup_session_handles_empty_argv(self):
        """Test _setup_session handles empty sys.argv gracefully."""
        client = object.__new__(BaseClient)

        with patch('sys.argv', []):
            client._setup_session('test-client')

        assert client.script_id == 'python'

    @patch('rucio.client.baseclient.config_get')
    def test_configure_hosts_uses_provided_values(self, mock_config, mock_client_partial):
        """Test _configure_hosts uses explicitly provided hosts."""
        mock_client_partial._get_config_value = Mock()

        mock_client_partial._configure_hosts('https://custom-rucio', 'https://custom-auth')

        assert mock_client_partial.host == 'https://custom-rucio'
        assert mock_client_partial.auth_host == 'https://custom-auth'
        mock_client_partial._get_config_value.assert_not_called()

    @patch('rucio.client.baseclient.config_get')
    def test_configure_hosts_falls_back_to_config(self, mock_config_get, mock_client_partial):
        """Test _configure_hosts reads from config when hosts not provided."""
        mock_client_partial.logger = Mock()

        # Mock config_get to return appropriate values based on option
        def config_get_side_effect(section, option, raise_exception=True, default=None):
            if option == 'rucio_host':
                return 'https://rucio_host.cern.ch'
            elif option == 'auth_host':
                return 'https://auth_host.cern.ch'
            elif option == 'trace_host':
                if not raise_exception:
                    return default
                raise NoSectionError(section)
            return f'https://{option}.cern.ch'

        mock_config_get.side_effect = config_get_side_effect

        mock_client_partial._configure_hosts(None, None)

        assert mock_client_partial.host == 'https://rucio_host.cern.ch'
        assert mock_client_partial.auth_host == 'https://auth_host.cern.ch'
        assert mock_client_partial.trace_host == 'https://rucio_host.cern.ch'  # Falls back to host

    @patch.dict(os.environ, {'RUCIO_ACCOUNT': 'env_account', 'RUCIO_VO': 'env_vo'})
    def test_configure_account_and_vo_from_environment(self, mock_client_partial):
        """Test _configure_account_and_vo reads from environment variables."""
        mock_client_partial._get_optional_config = Mock(return_value=None)

        mock_client_partial._configure_account_and_vo(None, None)

        assert mock_client_partial.account == 'env_account'
        assert mock_client_partial.vo == 'env_vo'

    @patch.dict(os.environ, {}, clear=True)
    @patch('rucio.client.baseclient.config_get')
    def test_configure_account_and_vo_from_config(self, mock_config_get, mock_client_partial):
        """Test _configure_account_and_vo reads from config file."""
        mock_client_partial.logger = Mock()

        # Mock config_get to return different values based on the option parameter
        def config_get_side_effect(section, option, raise_exception=True, default=None):
            if option == 'account':
                return 'config_account'
            elif option == 'vo':
                return 'config_vo'
            return default

        mock_config_get.side_effect = config_get_side_effect

        mock_client_partial._configure_account_and_vo(None, None)

        assert mock_client_partial.account == 'config_account'
        assert mock_client_partial.vo == 'config_vo'


    @patch.dict(os.environ, {}, clear=True)
    @patch('rucio.client.baseclient.config_get')
    def test_configure_account_and_vo_defaults_vo(self, mock_config_get, mock_client_partial):
        """Test _configure_account_and_vo uses DEFAULT_VO as fallback."""
        from rucio.common.constants import DEFAULT_VO

        mock_client_partial.logger = Mock()

        # Mock config_get to return None for both account and vo
        mock_config_get.return_value = None

        mock_client_partial._configure_account_and_vo(None, None)

        assert mock_client_partial.vo == DEFAULT_VO

    @pytest.mark.parametrize("url", ["https://example.com", "http://example.com"])
    def test_get_valid_url_scheme_accepts_valid_schemes(self, mock_client_partial, url):
        """Test _get_valid_url_scheme accepts allowed protocols and returns scheme."""
        result = mock_client_partial._get_valid_url_scheme(url, ['http', 'https'])
        assert result in ['http', 'https']

    @pytest.mark.parametrize("url,exception", [
        ("example.com", ClientProtocolNotFound),
        ("ftp://example.com", ClientProtocolNotSupported)
    ])
    def test_get_valid_url_scheme_rejects_invalid(self, mock_client_partial, url, exception):
        """Test _get_valid_url_scheme raises on invalid protocols."""
        with pytest.raises(exception):
            mock_client_partial._get_valid_url_scheme(url, ['http', 'https'])

    @pytest.mark.parametrize("env_var,expected_path", [
        ({'X509_CERT_DIR': '/test/certs'}, '/test/certs'),
        ({}, True)  # Falls back to certifi (True)
    ])
    @patch('rucio.client.baseclient.config_get')
    def test_discover_ca_cert_from_sources(self, mock_config, mock_client_partial, env_var, expected_path):
        """Test _discover_ca_cert finds cert from various sources."""
        from rucio.common.exception import ConfigNotFound

        if expected_path is True:
            mock_config.side_effect = ConfigNotFound()
        else:
            mock_config.return_value = '/config/ca_cert.pem'

        with patch.dict(os.environ, env_var, clear=True):
            result = mock_client_partial._discover_ca_cert()

        assert result == expected_path


class TestBaseClientOIDCFlows:
    """Test OIDC authentication flow methods."""

    # Test constants
    AUTH_URL = 'https://iam.example.com/authorize'
    TEST_TOKEN = 'test_token'

    @pytest.fixture
    def mock_oidc_client(self):
        """Create BaseClient mock with OIDC configuration."""
        client = object.__new__(BaseClient)
        client.logger = Mock()
        client.creds = {
            'oidc_scope': 'openid profile',
            'oidc_auto': False,
            'oidc_polling': False,
            'oidc_audience': 'rucio',
            'oidc_issuer': 'https://iam.example.com',
            'oidc_refresh_lifetime': 86400,
            'oidc_username': 'testuser',
            'oidc_password': 'testpass'
        }
        client.auth_host = 'https://auth.example.com'
        client._send_request = Mock()
        return client

    @pytest.fixture
    def success_response(self):
        """Create a successful auth response."""
        response = Mock()
        response.headers = {'X-Rucio-Auth-Token': self.TEST_TOKEN}
        response.status_code = codes.ok
        return response

    @pytest.fixture
    def fail_response(self):
        """Create a failed auth response."""
        response = Mock()
        response.headers = {}
        response.status_code = codes.unauthorized
        return response

    @pytest.mark.parametrize("has_audience,has_issuer", [
        (True, True),
        (False, False)
    ])
    def test_build_oidc_request_headers_optional_fields(self, mock_oidc_client, has_audience, has_issuer):
        """Test _build_oidc_request_headers includes/omits optional fields."""
        if not has_audience:
            mock_oidc_client.creds['oidc_audience'] = None
        if not has_issuer:
            mock_oidc_client.creds['oidc_issuer'] = None

        headers = mock_oidc_client._build_oidc_request_headers()

        assert headers['X-Rucio-Client-Authorize-Scope'] == 'openid profile'
        assert ('X-Rucio-Client-Authorize-Audience' in headers) == has_audience
        assert ('X-Rucio-Client-Authorize-Issuer' in headers) == has_issuer

    @pytest.mark.parametrize("has_header,expected", [
        (True, 'https://iam.example.com/auth'),
        (False, None)
    ])
    def test_request_oidc_auth_url_response_handling(self, mock_oidc_client, has_header, expected):
        """Test _request_oidc_auth_url handles response variations."""
        mock_response = Mock()
        mock_response.headers = {'X-Rucio-OIDC-Auth-URL': expected} if has_header else {}
        mock_response.text = 'success'
        mock_oidc_client._send_request.return_value = mock_response

        url = mock_oidc_client._request_oidc_auth_url()

        assert url == expected

    @patch('builtins.print')
    @patch('time.time')
    def test_handle_oidc_polling_flow_succeeds_on_token(self, mock_time, mock_print, mock_oidc_client):
        """Test _handle_oidc_polling_flow returns token on success."""
        mock_time.return_value = 1000
        mock_response = Mock()
        mock_response.headers = {'X-Rucio-Auth-Token': 'test_token'}
        mock_response.status_code = codes.ok
        mock_oidc_client._send_request.return_value = mock_response

        result = mock_oidc_client._handle_oidc_polling_flow('https://auth.example.com/oidc')

        assert result == mock_response
        assert mock_response.headers['X-Rucio-Auth-Token'] == 'test_token'

    @patch('builtins.print')
    @patch('time.time')
    @patch('time.sleep')
    def test_handle_oidc_polling_flow_times_out(self, mock_sleep, mock_time, mock_print, mock_oidc_client):
        """Test _handle_oidc_polling_flow returns None on timeout."""
        mock_time.side_effect = [0, OIDC_POLLING_TIMEOUT_SECONDS + 1]
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = codes.unauthorized
        mock_oidc_client._send_request.return_value = mock_response

        result = mock_oidc_client._handle_oidc_polling_flow('https://auth.example.com/oidc')

        assert result is None

    @patch('builtins.print')
    @patch('builtins.input')
    def test_handle_oidc_manual_code_flow_succeeds_first_try(self, mock_input, mock_print, mock_oidc_client):
        """Test _handle_oidc_manual_code_flow succeeds with valid code."""
        mock_input.return_value = 'valid_code_123'
        mock_response = Mock()
        mock_response.headers = {'X-Rucio-Auth-Token': 'test_token'}
        mock_response.status_code = codes.ok
        mock_oidc_client._send_request.return_value = mock_response

        result = mock_oidc_client._handle_oidc_manual_code_flow('https://auth.example.com/oidc')

        assert result == mock_response
        mock_input.assert_called_once()

    @patch('builtins.print')
    @patch('builtins.input')
    def test_handle_oidc_manual_code_flow_retries_on_failure(self, mock_input, mock_print, mock_oidc_client):
        """Test _handle_oidc_manual_code_flow allows multiple attempts."""
        mock_input.side_effect = ['invalid1', 'invalid2', 'valid_code']

        # First two attempts fail
        fail_response = Mock()
        fail_response.headers = {}
        fail_response.status_code = codes.unauthorized

        # Third attempt succeeds
        success_response = Mock()
        success_response.headers = {'X-Rucio-Auth-Token': 'test_token'}
        success_response.status_code = codes.ok

        mock_oidc_client._send_request.side_effect = [fail_response, fail_response, success_response]

        result = mock_oidc_client._handle_oidc_manual_code_flow('https://auth.example.com/oidc')

        assert result == success_response
        assert mock_input.call_count == 3

    @patch('builtins.print')
    @patch('builtins.input')
    def test_handle_oidc_manual_code_flow_fails_after_max_attempts(self, mock_input, mock_print, mock_oidc_client):
        """Test _handle_oidc_manual_code_flow returns None after max attempts."""
        mock_input.return_value = 'invalid_code'
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = codes.unauthorized
        mock_oidc_client._send_request.return_value = mock_response

        result = mock_oidc_client._handle_oidc_manual_code_flow('https://auth.example.com/oidc')

        assert result is None
        assert mock_input.call_count == OIDC_MAX_CODE_ATTEMPTS

    @patch('builtins.print')
    def test_handle_oidc_auto_flow_succeeds(self, mock_print, mock_oidc_client):
        """Test _handle_oidc_auto_flow completes authentication."""
        mock_oidc_client.creds['oidc_auto'] = True

        auth_response = Mock()
        auth_response.url = 'https://iam.example.com/login'

        login_response = Mock()
        login_response.url = 'https://auth.example.com/callback'
        login_response.text = 'success'
        login_response.headers = {'X-Rucio-Auth-Token': 'test_token'}
        login_response.status_code = codes.ok

        mock_oidc_client._send_request.side_effect = [auth_response, login_response]

        result = mock_oidc_client._handle_oidc_auto_flow('https://iam.example.com/authorize')

        assert result == login_response

    @patch('builtins.print')
    def test_handle_oidc_auto_flow_handles_oauth_error(self, mock_print, mock_oidc_client):
        """Test _handle_oidc_auto_flow returns None on OAuth error."""
        mock_oidc_client.creds['oidc_auto'] = True

        auth_response = Mock()
        auth_response.url = 'https://iam.example.com/login'

        error_response = Mock()
        error_response.text = 'OAuth Error: Invalid client configuration'

        mock_oidc_client._send_request.side_effect = [auth_response, error_response]

        result = mock_oidc_client._handle_oidc_auto_flow('https://iam.example.com/authorize')

        assert result is None

    def test_finalize_oidc_token_extracts_token(self, mock_oidc_client):
        """Test _finalize_oidc_token extracts and stores auth token."""
        mock_oidc_client.auth_oidc_refresh_active = False

        mock_response = Mock()
        mock_response.headers = {'x-rucio-auth-token': 'extracted_token'}
        mock_response.status_code = codes.ok

        result = mock_oidc_client._finalize_oidc_token(mock_response)

        assert result is True
        assert mock_oidc_client.auth_token == 'extracted_token'

    def test_finalize_oidc_token_handles_none_response(self, mock_oidc_client):
        """Test _finalize_oidc_token returns False on None input."""
        result = mock_oidc_client._finalize_oidc_token(None)

        assert result is False

    def test_finalize_oidc_token_raises_on_error_status(self, mock_oidc_client):
        """Test _finalize_oidc_token raises exception on error response."""
        from rucio.common.exception import CannotAuthenticate

        mock_response = Mock()
        mock_response.status_code = codes.unauthorized
        mock_response.headers = {}
        mock_response.content = b'Authentication failed'

        mock_oidc_client._get_exception = Mock(return_value=(CannotAuthenticate, 'Auth failed'))

        with pytest.raises(CannotAuthenticate):
            mock_oidc_client._finalize_oidc_token(mock_response)

    def test_auto_authorize_oidc_scopes_constructs_form(self, mock_oidc_client):
        """Test _auto_authorize_oidc_scopes builds authorization form."""
        mock_oidc_client.creds['oidc_scope'] = 'openid profile email'
        mock_response = Mock()
        mock_oidc_client._send_request.return_value = mock_response

        result = mock_oidc_client._auto_authorize_oidc_scopes('https://iam.example.com/authorize')

        call_args = mock_oidc_client._send_request.call_args
        form_data = call_args[1]['data']

        assert 'scope_openid' in form_data
        assert 'scope_profile' in form_data
        assert 'scope_email' in form_data
        assert form_data['user_oauth_approval'] is True
        assert result == mock_response
