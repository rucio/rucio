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

import io
from unittest.mock import patch

import pytest
import requests

from rucio.client.baseclient import BaseClient
from rucio.common.config import config_set
from tests.helpers.keycloak_helper import ExternalKeycloakHelper


@pytest.fixture
def client_token_path_override(file_config_mock, function_scope_prefix, tmp_path):
    """
    Ensure each running client has a different path for the token, otherwise tests cannot run in parallel
    """
    config_set('client', 'auth_token_file_path', str(tmp_path / f'{function_scope_prefix}token'))


@pytest.mark.external
class TestBaseClientOIDCExternalAPI:
    """
    External API tests that verify OIDC server endpoints without invoking internal BaseClient functions.
    
    Rationale for keeping these tests:
    - Server-side Validation: Verify OIDC server endpoints work correctly
    - Configuration Validation: Test server-side OIDC integration setup
    - Endpoint Contract Testing: Ensure API contracts haven't changed
    - Environment Validation: Confirm server environment is properly configured
    
    These tests serve the purpose: "Does the OIDC server integration work as expected?"
    They complement internal tests which answer: "Does BaseClient integrate with the server correctly?"
    """
    
    def test_baseclient_oidc_integration_endpoint(self, vo):
        """Test that OIDC server-side integration is properly configured"""
        keycloak = ExternalKeycloakHelper()
        
        if not keycloak.is_available():
            pytest.skip("Keycloak not available for integration test")
        
        # Test the OIDC endpoint directly - this verifies all server-side config
        response = requests.get('https://rucio/auth/oidc',
                              headers={
                                  'X-Rucio-Client-Authorize-Auto': 'True',
                                  'X-Rucio-Client-Authorize-Issuer': f'{keycloak.keycloak_url}/realms/{keycloak.realm}',
                                  'X-Rucio-Client-Authorize-Audience': 'rucio'
                              }, verify=False)
        
        # These assertions verify the entire OIDC integration chain
        assert response.status_code == 200, f"OIDC endpoint failed: {response.text}"
        assert 'X-Rucio-OIDC-Auth-URL' in response.headers, "No auth URL generated"
        
        auth_url = response.headers['X-Rucio-OIDC-Auth-URL']
        assert keycloak.keycloak_url in auth_url, "Auth URL doesn't point to Keycloak"
        assert 'client_id=rucio-test-client' in auth_url, "Wrong client_id in URL"
        assert 'scope=openid+profile' in auth_url, "Missing scopes"
        assert 'audience=rucio' in auth_url, "Missing audience"


@pytest.mark.integration
class TestBaseClientOIDCIntegration:
    """
    Integration tests that verify BaseClient OIDC authentication works correctly with real servers.
    
    These tests invoke internal BaseClient functions and verify they integrate properly with
    external OIDC services. They complement the external API tests by proving our client codes
    works with the verified server endpoints.
    """
    
    def test_baseclient_oidc_manual_code_branch(self, vo, client_token_path_override):
        """
        Test that verifies manual code branch is reached and behaves correctly.
        
        Note: This test only verifies branch execution up to the user interaction point.
        A full end-to-end test of the manual code flow (including browser redirect,
        user authentication, and code entry) would require E2E testing tools with
        browser automation (e.g. Selenium, Playwright) and is beyond the scope
        of this integration test.
        
        This test validates:
        - Correct branch selection logic (manual vs polling vs auto)
        - Auth URL generation and structure
        - User prompt messages
        - Integration with Keycloak up to the user interaction boundary
        """
        
        keycloak = ExternalKeycloakHelper()
        if not keycloak.is_available():
            pytest.skip("Keycloak not available")
            
        creds = {
            'oidc_auto': False,      # Enter manual flow
            'oidc_polling': False,   # Hit manual code branch
            'oidc_username': 'testuser',
            'oidc_password': 'testpass123',
            'oidc_scope': 'openid profile',
            'oidc_audience': 'rucio',
            'oidc_issuer': f'{keycloak.keycloak_url}/realms/{keycloak.realm}',
            'oidc_refresh_lifetime': None
        }
        
        captured_output = io.StringIO()
        
        with patch('sys.stdout', captured_output):
            try:
                _ = BaseClient(
                    rucio_host='https://rucio',
                    auth_host='https://rucio',
                    account='root',
                    ca_cert=None,
                    auth_type='oidc',
                    creds=creds,
                    vo=vo
                )
                pytest.fail("Should not succeed without user input")
            except Exception:
                # Expected to fail due to EOF on input()
                pass
        
        output = captured_output.getvalue()
        
        # Verify the branch was reached by checking output messages
        assert "Copy paste the code from the browser" in output, "Manual code branch not reached"
        assert "authenticate with your Identity Provider" in output, "Auth prompt not shown"
        assert "https://" in output, "Auth URL not generated"
        
        # Verify it's NOT the polling branch
        assert "polling" not in output.lower(), "Should not show polling messages"
        
        # Extract the auth URL from output
        lines = output.split('\n')
        auth_url_line = [line for line in lines if 'https://' in line and 'auth' in line]
        
        if auth_url_line:
            auth_url = auth_url_line[0].strip()
            # Verify URL structure
            assert 'oidc_redirect' in auth_url, "Should contain oidc_redirect endpoint"
            assert '?' in auth_url, "Should contain auth code parameter"
            
        
    def test_baseclient_oidc_polling_branch(self, vo, client_token_path_override):
        """
        Test polling branch with reliable timeout mechanism
        
        Note: This test validates polling logic up to the server interaction boundary.
        It cannot test the complete polling cycle where a user authenticates in a browser
        and the server eventually returns a token, as this would require browser automation
        and user interaction beyond the scope of integration testing.
        
        This test validates:
        - Correct branch selection (polling vs manual vs auto)
        - Polling loop initialization and timeout setup
        - User prompt messages and timeout communication
        - Integration with Keycloak up to the polling request phase
        """
        
        keycloak = ExternalKeycloakHelper()
        if not keycloak.is_available():
            pytest.skip("Keycloak not available")
            
        creds = {
            'oidc_auto': False,
            'oidc_polling': True,
            'oidc_username': 'testuser',
            'oidc_password': 'testpass123',
            'oidc_scope': 'openid profile',
            'oidc_audience': 'rucio',
            'oidc_issuer': f'{keycloak.keycloak_url}/realms/{keycloak.realm}',
            'oidc_refresh_lifetime': None
        }
        
        import threading
        import time
        
        # Use a flag to interrupt the test
        timeout_occurred = threading.Event()
        
        def timeout_callback():
            timeout_occurred.set()
        
        # Set up timer
        timer = threading.Timer(2.0, timeout_callback)
        timer.start()
        
        captured_output = io.StringIO()
        
        try:
            with patch('sys.stdout', captured_output):
                # Mock time.time() to accelerate timeout
                original_time = time.time
                start_time = original_time()
                
                def mock_time():
                    if timeout_occurred.is_set():
                        # Force timeout by returning time 200 seconds in future
                        return start_time + 200
                    return original_time()
                
                with patch('time.time', side_effect=mock_time):
                    with patch('time.sleep'):  # Skip actual sleep
                        try:
                            _ = BaseClient(
                                rucio_host='https://rucio',
                                auth_host='https://rucio',
                                account='root',
                                ca_cert=None,
                                auth_type='oidc',
                                creds=creds,
                                vo=vo
                            )
                        except Exception:
                            pass  # Expected to fail
        finally:
            timer.cancel()
        
        output = captured_output.getvalue()
        
        # Verify polling branch was reached
        assert "polling" in output.lower(), "Polling branch not reached"
        assert "3 minutes" in output, "Polling message not shown"
        assert "Copy paste" not in output, "Should not show manual code message"

    def test_baseclient_oidc_auto_with_keycloak(self, vo, client_token_path_override):
        """
        Test BaseClient OIDC auto authentication against real Keycloak
        
        DEPRECATED: This test covers the oidc_auto=True branch which violates OAuth2/OIDC
        security standards by sharing user credentials with third-party applications.
        This branch is planned for removal in future versions.
        
        TODO: Remove this test when oidc_auto functionality is deprecated and removed.
        """
        keycloak = ExternalKeycloakHelper()
        
        if not keycloak.is_available():
            pytest.skip("Keycloak not available for integration test")
        
        creds = {
            'oidc_auto': True,  # This functionality will be deprecated
            'oidc_username': 'testuser',
            'oidc_password': 'testpass123',
            'oidc_scope': 'openid profile',
            'oidc_audience': 'rucio',
            'oidc_issuer': f'{keycloak.keycloak_url}/realms/{keycloak.realm}'
        }
        
        captured_output = io.StringIO()

        with patch('sys.stdout', captured_output):
            try:
                _ = BaseClient(
                    rucio_host='https://rucio',
                    auth_host='https://rucio',
                    account='root',
                    ca_cert=None,
                    auth_type='oidc',
                    creds=creds,
                    vo=vo
                )
                        
            except Exception:
                pass  # Test passes

        output = captured_output.getvalue()
        
        # Verify the branch was reached by checking output messages
        assert "According to the OAuth2/OIDC standard you should NOT be sharing" in output, "oidc_auto=True branch not reached"
        assert "your password with any 3rd party application, therefore," in output, "oidc_auto=True branch not reached"
        assert "we strongly discourage you from following this --oidc-auto approach." in output, "oidc_auto=True branch not reached"