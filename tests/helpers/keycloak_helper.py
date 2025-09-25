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

import time

import requests


class ExternalKeycloakHelper:
    """Simplified helper for pre-configured Keycloak instance"""
    
    def __init__(self, base_url='http://dev-keycloak-1:8080', realm='rucio-test'):
        self.base_url = base_url
        self.realm = realm
        self.keycloak_url = self.base_url
        
    def wait_for_ready(self, timeout=30):
        """Wait for external Keycloak to be ready"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f'{self.keycloak_url}/health/ready', timeout=5)
                if response.status_code == 200:
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(2)
        return False
    
    def get_user_token(self):
        """Get user access token for testing - assumes realm/client/user exist"""
        response = requests.post(
            f'{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token',
            data={
                'grant_type': 'password',
                'client_id': 'rucio-test-client',
                'client_secret': 'rucio-test-secret',
                'username': 'testuser',
                'password': 'testpass123',
                'scope': 'openid profile'
            }
        )
        response.raise_for_status()
        return response.json()
    
    def get_client_credentials_token(self, scope='profile'):
        """Get client credentials token"""
        response = requests.post(
            f'{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': 'rucio-test-client',
                'client_secret': 'rucio-test-secret',
                'scope': scope
            }
        )
        response.raise_for_status()
        return response.json()
    
    def refresh_token(self, refresh_token):
        """Refresh an access token"""
        response = requests.post(
            f'{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token',
            data={
                'grant_type': 'refresh_token',
                'client_id': 'rucio-test-client',
                'client_secret': 'rucio-test-secret',
                'refresh_token': refresh_token
            }
        )
        response.raise_for_status()
        return response.json()
    
    def is_available(self):
        """Check if Keycloak is available"""
        try:
            response = requests.get(f'{self.keycloak_url}/health/ready', timeout=5)
            return response.status_code == 200
        except Exception:
            return False