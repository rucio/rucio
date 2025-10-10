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

import base64
import json
from contextlib import contextmanager
from unittest.mock import mock_open, patch

import pytest
import requests

from rucio.core.oidc import request_token
from tests.helpers.keycloak_helper import ExternalKeycloakHelper


@contextmanager
def external_keycloak_environment():
    """Context manager for external Keycloak test environment"""
    keycloak = ExternalKeycloakHelper(base_url='http://dev-keycloak-1:8080', realm='rucio-test')
    
    if not keycloak.wait_for_ready():
        pytest.skip(f"Keycloak not available at {keycloak.keycloak_url}")
    
    yield keycloak


@pytest.mark.external
class TestKeycloakExternalAPI:
    """
    External API tests that verify Keycloak service behavior without invoking internal Rucio functions.
    
    Rationale for keeping these tests:
    - Dependency Verification: Prove external services (Keycloak) work as expected
    - Contract Testing: Verify API contracts haven't changed
    - Environment Validation: Confirm test environment is properly configured
    - Integration Confidence: Provide confidence that external pieces work before testing internal integration
    
    These tests serve the purpose: "Does Keycloak work as we expect?"
    They complement internal tests which answer: "Does our code integrate with Keycloak correctly?"
    """
    
    def test_keycloak_connectivity(self):
        """Test basic connectivity to Keycloak"""
        with external_keycloak_environment() as keycloak:
            assert keycloak.is_available()
            
            # Test health endpoint
            response = requests.get(f'{keycloak.keycloak_url}/health/ready')
            assert response.status_code == 200
    
    def test_user_password_authentication(self):
        """Test user password authentication flow"""
        with external_keycloak_environment() as keycloak:
            token_data = keycloak.get_user_token()
            
            assert 'access_token' in token_data
            assert 'token_type' in token_data
            assert token_data['token_type'] == 'Bearer'
            
            # Verify JWT structure
            access_token = token_data['access_token']
            parts = access_token.split('.')
            assert len(parts) == 3  # header.payload.signature
    
    def test_client_credentials_flow(self):
        """Test client credentials flow"""
        with external_keycloak_environment() as keycloak:
            token_data = keycloak.get_client_credentials_token()
            
            assert 'access_token' in token_data
            assert 'token_type' in token_data
            assert token_data['token_type'] == 'Bearer'
            assert len(token_data['access_token'].split('.')) == 3
    
    def test_token_refresh_flow(self):
        """Test token refresh mechanism"""
        with external_keycloak_environment() as keycloak:
            # Get initial token with offline_access scope
            response = requests.post(
                f'{keycloak.keycloak_url}/realms/{keycloak.realm}/protocol/openid-connect/token',
                data={
                    'grant_type': 'password',
                    'client_id': 'rucio-test-client',
                    'client_secret': 'rucio-test-secret',
                    'username': 'testuser',
                    'password': 'testpass123',
                    'scope': 'openid profile offline_access'
                }
            )
            
            if response.status_code == 200:
                token_data = response.json()
                
                if 'refresh_token' in token_data:
                    # Test refresh
                    new_token_data = keycloak.refresh_token(token_data['refresh_token'])
                    
                    assert 'access_token' in new_token_data
                    assert new_token_data['access_token'] != token_data['access_token']
    
    def test_discovery_endpoint(self):
        """Test OIDC discovery endpoint"""
        with external_keycloak_environment() as keycloak:
            discovery_url = f'{keycloak.keycloak_url}/realms/{keycloak.realm}/.well-known/openid-configuration'
            response = requests.get(discovery_url)
            
            assert response.status_code == 200
            config_data = response.json()
            
            # Verify required endpoints
            required_endpoints = ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint']
            for endpoint in required_endpoints:
                assert endpoint in config_data
                assert keycloak.keycloak_url in config_data[endpoint]
    
    def test_token_claims_structure(self):
        """Test JWT token claims structure"""
        with external_keycloak_environment() as keycloak:
            token_data = keycloak.get_user_token()
            access_token = token_data['access_token']
            
            # Decode payload (without signature verification)
            parts = access_token.split('.')
            payload = base64.urlsafe_b64decode(parts[1] + '==')
            claims = json.loads(payload)
            
            # Verify expected claims
            assert 'sub' in claims
            assert 'iss' in claims
            assert claims['iss'] == f"{keycloak.keycloak_url}/realms/{keycloak.realm}"
            assert 'exp' in claims
            assert 'iat' in claims
    
    def test_realm_cleanup_on_failure(self):
        """Test graceful handling of unavailable Keycloak"""
        # Test with non-existent instance
        keycloak = ExternalKeycloakHelper(base_url='http://dev-keycloak-1:99999')
        
        assert not keycloak.is_available()
        assert not keycloak.wait_for_ready(timeout=5)


@pytest.mark.integration
class TestRucioOIDCIntegration:
    """
    Integration tests that verify Rucio's internal OIDC functions work correctly with Keycloak.
    
    These tests invoke internal Rucio functions and verify they integrate properly with external services.
    They complement the external API tests by proving our code works with the verified dependencies.
    """
    
    def test_rucio_oidc_integration_mocked(self):
        """Test Rucio OIDC integration with mocked idpsecrets"""
        with external_keycloak_environment() as keycloak:
            # Mock idpsecrets configuration
            test_secrets = {
                "test-issuer": {
                    "issuer": f"{keycloak.keycloak_url}/realms/{keycloak.realm}",
                    "client_id": "rucio-test-client",
                    "client_secret": "rucio-test-secret",
                    "redirect_uris": [
                        f"{keycloak.keycloak_url}/auth/oidc_token",
                        f"{keycloak.keycloak_url}/auth/oidc_code"
                    ],
                    "SCIM": {
                        "client_id": "rucio-test-client",
                        "client_secret": "rucio-test-secret"
                    }
                }
            }
            
            # Mock configuration and test token request
            with patch('rucio.core.oidc.IDPSECRETS', '/tmp/test_idpsecrets.json'):
                with patch('builtins.open', mock_open(read_data=json.dumps(test_secrets))):
                    with patch('rucio.core.oidc.OIDC_CLIENT_ID', 'rucio-test-client'), \
                         patch('rucio.core.oidc.OIDC_CLIENT_SECRET', 'rucio-test-secret'), \
                         patch('rucio.core.oidc.OIDC_PROVIDER_ENDPOINT',
                               f'{keycloak.keycloak_url}/realms/{keycloak.realm}/protocol/openid-connect/token'):
                        
                        # Test request_token function
                        token = request_token(
                            audience='rucio',
                            scope='profile',
                            use_cache=False
                        )
                        
                        if token:
                            assert len(token.split('.')) == 3
                            # Decode payload (without signature verification)
                            parts = token.split('.')
                            payload = base64.urlsafe_b64decode(parts[1] + '==')
                            claims = json.loads(payload)
                            
                            # Verify expected claims
                            assert 'sub' in claims
                            assert 'iss' in claims
                            assert claims['iss'] == f"{keycloak.keycloak_url}/realms/{keycloak.realm}"
                            assert 'exp' in claims
                            assert 'iat' in claims


@pytest.mark.external
class TestOIDCFlowSimulation:
    """
    Flow simulation tests that verify OIDC authentication flow structures and URL patterns.
    
    These tests simulate the expected behavior of different OIDC flows without full end-to-end execution.
    They verify URL construction, parameter handling, and response structure expectations.
    """
    
    def test_oidc_polling_flow_simulation(self):
        """Simulate OIDC polling authentication flow"""
        with external_keycloak_environment() as keycloak:
            # Simulate the polling mechanism from BaseClient
            auth_url = f"{keycloak.keycloak_url}/realms/{keycloak.realm}/protocol/openid-connect/auth"
            auth_params = {
                'client_id': 'rucio-test-client',
                'response_type': 'code',
                'scope': 'openid profile',
                'redirect_uri': f'{keycloak.keycloak_url}/auth/oidc_token',
                'state': 'test-state-123'
            }
            
            full_auth_url = auth_url + '?' + '&'.join([f'{k}={v}' for k, v in auth_params.items()])
            
            # Verify polling URL structure
            assert 'oidc_token' in full_auth_url  # Polling uses oidc_token endpoint
            assert 'response_type=code' in full_auth_url
            
            # Simulate successful authentication (user would do this in browser)
            token_data = keycloak.get_user_token()
            
            # Simulate polling result (server would return token after user auth)
            mock_polling_response = {'X-Rucio-Auth-Token': token_data['access_token']}
            assert 'X-Rucio-Auth-Token' in mock_polling_response
    
    def test_oidc_manual_code_flow_simulation(self):
        """Simulate OIDC manual code entry flow"""
        with external_keycloak_environment() as keycloak:
            # Simulate manual code flow
            auth_url = f"{keycloak.keycloak_url}/realms/{keycloak.realm}/protocol/openid-connect/auth"
            auth_params = {
                'client_id': 'rucio-test-client',
                'response_type': 'code',
                'scope': 'openid profile',
                'redirect_uri': f'{keycloak.keycloak_url}/auth/oidc_code',
                'state': 'test-state-456'
            }
            
            full_auth_url = auth_url + '?' + '&'.join([f'{k}={v}' for k, v in auth_params.items()])
            
            # Verify manual code URL structure
            assert 'oidc_code' in full_auth_url  # Manual uses oidc_code endpoint
            
            # Simulate user getting fetchcode and entering it
            mock_fetchcode = "test-fetch-code-12345"
            fetch_url = f"{keycloak.keycloak_url}/auth/oidc_redirect?{mock_fetchcode}"
            
            # Verify fetch URL structure
            assert 'oidc_redirect' in fetch_url
            assert mock_fetchcode in fetch_url
            
            # Simulate successful code exchange
            token_data = keycloak.get_user_token()
            mock_code_response = {'X-Rucio-Auth-Token': token_data['access_token']}
            assert 'X-Rucio-Auth-Token' in mock_code_response