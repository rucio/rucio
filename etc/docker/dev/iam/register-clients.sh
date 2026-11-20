#!/bin/sh
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

# Register the OAuth2 clients used by the dev environment in INDIGO IAM.
#
# IAM runs with the h2-test profile, which provides the admin-client-rw client.
# Its token is used to create the clients through the IAM client management API
# with fixed IDs and secrets, so rucio/idpsecrets.json and fts/entrypoint.sh
# can reference them statically. Safe to re-run: existing clients are kept.

set -eu

IAM_URL=${IAM_URL:-https://indigoiam}

token=$(curl -sS --fail --retry 10 --retry-all-errors --retry-delay 3 "$IAM_URL/token" \
    -d grant_type=client_credentials \
    -d client_id=admin-client-rw -d client_secret=secret \
    -d scope=iam:admin.write \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || { echo "Failed to obtain IAM admin token" >&2; exit 1; }

register() {
    code=$(curl -sS -o /tmp/response -w '%{http_code}' -X POST "$IAM_URL/iam/api/clients" \
        -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$2")
    if [ "$code" = 201 ]; then
        echo "$1: registered"
    elif [ "$code" = 400 ] && grep -q 'Client id not available' /tmp/response; then
        echo "$1: already registered"
    else
        echo "$1: registration failed (HTTP $code): $(cat /tmp/response)" >&2
        exit 1
    fi
}

# Used by the Rucio server (see rucio/idpsecrets.json)
register rucio '{
  "client_id": "85e6f7a5-580b-4a1c-a6d2-39055143063d",
  "client_secret": "AIYIneAVGs9PTVvQnxNGqDmh3rNTsyFOrrwRIqy1Zc6ngPN9hQe6I2VzDzN2uGLCPsvQI8nhYxf_V09NHk-yv7o",
  "client_name": "rucio",
  "grant_types": ["authorization_code", "client_credentials", "refresh_token", "password", "implicit",
                  "urn:ietf:params:oauth:grant-type:token-exchange"],
  "scope": "openid profile email offline_access fts storage.read:/ storage.modify:/ scim:read ruciodev",
  "redirect_uris": ["https://rucio/auth/oidc_token", "https://rucio/auth/oidc_code", "https://rucio/auth/oidc_redirect"],
  "token_endpoint_auth_method": "client_secret_basic"
}'

# Used by Rucio for SCIM queries (see "SCIM" in rucio/idpsecrets.json)
register rucio_scim '{
  "client_id": "11034667-5c50-4c9a-8f43-6a48090dced2",
  "client_secret": "eIcPpu5HbjuECyTVUB0iBAwPgIDEaJUm8T4xpsn5tyWH53CTxoG9cH2Vo6etYMWegPeWffdbrEPwwkOJZCHUgQ",
  "client_name": "rucio_scim",
  "grant_types": ["client_credentials"],
  "scope": "openid profile email address phone scim:read",
  "token_endpoint_auth_method": "client_secret_basic"
}'

# Used by FTS for token exchange (see t_token_provider in fts/entrypoint.sh)
register fts3 '{
  "client_id": "d6dad80f-11f7-4cf4-a4ef-fbd081ec7f98",
  "client_secret": "AJWL5JZtM6I2iaj7XHYq98kPGo6-8Wde2ScSHJhHNvCLeKppTj9fBmeq2xGWi3RCFlj6cPJFjz-BxXIBva4kDYo",
  "client_name": "fts3",
  "grant_types": ["client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "scope": "openid profile email offline_access storage.read:/ storage.modify:/",
  "token_endpoint_auth_method": "client_secret_basic"
}'
