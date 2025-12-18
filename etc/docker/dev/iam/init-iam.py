#!/usr/bin/env python3
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

"""
IAM Setup Script
Configures INDIGO IAM clients and updates authentication configuration.

## Overview

This script automates the registration of OAuth2/OIDC clients required for Rucio and FTS
(File Transfer Service) integration with INDIGO IAM, and updates their respective
configuration files and database entries. Its uses the `h2-test` profile in indigoIAM
which provided predefined client with admin scopes. Info about it provided here
https://github.com/indigo-iam/iam/discussions/678

## Procedure

The script executes the following workflow:

### 1. Initial Setup and Configuration
1. **Load Configuration**: Reads required credentials, database settings, and paths from
   environment variables (see Environment Variables section).
2. **Initialize IAM Client**: Creates an `IAMClient` instance to handle API requests to
   the IAM Issuer URL.
3. **Verify Configuration File**: Ensures the Rucio IDP secrets JSON file exists at the
   configured path.

### 2. IAM Client Registration & Configuration
1. **Obtain Admin Token**: Retrieves an access token using `admin-client-rw` credentials
   (client credentials grant) for administrative IAM API operations.
2. **Update Admin Client**: Updates the `admin-client-rw` client to ensure it has the
   required grant types (`client_credentials`, `password`) and scopes
   (`iam:admin.write`, `iam:admin.read`, `scim:write`, `scim:read`).
3. **Obtain User Admin Token**: Retrieves a token using the admin user's
   username/password(password grant). Required by IAM to register clients
   with the `client_credentials` grant type.
4. **Register Rucio Client**:
   Rucio's interactive web authentication using the Authorization Code Flow.
   Redirect URIs are provided for token exchange. Registers the OAuth2 client for
   Rucio's machine-to-machine storage operations using the Client Credentials Flow.
   This client has storage-specific scopes for storage endpoints.
5. **Register FTS Client** (`fts-client`): Registers the OAuth2 client for FTS
    operations,supporting Token Exchange and Refresh Token grants for
    non-interactive file transfers.

### 3. Configuration & Database Updates
1. **Update Rucio JSON Config**: Updates the Rucio IDP secrets file with:
   - `rucio` IAM client's credentials.
   - SCIM client credentials taken from h2_profile.
   - IAM issuer URL
   - Redirect URIs
2. **Update FTS Database**: Performs an UPSERT operation on the FTS MySQL database's
   `t_token_provider` table to store/update the `fts-client` credentials. This ensures
   FTS uses the correct OAuth2 client for token exchange operations.

## Environment Variables

### Required
- `IAM_ISSUER_URL`: The base URL of the INDIGO IAM instance (e.g., `https://iam.example.org/`)

### Optional (with defaults)
- `TEST_ADMIN_SCOPED_CLIENT_ID`: Admin client ID (default: `admin-client-rw`)
- `TEST_ADMIN_SCOPED_CLIENT_SECRET`: Admin client secret (default: `secret`)
- `ADMIN_USERNAME`: IAM admin username (default: `admin`)
- `ADMIN_PASSWORD`: IAM admin password (default: `password`)
- `RUCIO_IDPSECRETS_CONFIG_PATH`: Rucio IDP config file (default: `/auth_config.json`)
- `FTS_DB_HOST`: FTS database hostname (default: `ftsdb`)
- `FTS_DB_USER`: FTS database username (default: `fts`)
- `FTS_DB_PASSWORD`: FTS database password (default: `fts`)
- `FTS_DB_NAME`: FTS database name (default: `fts`)

## Requirements

- Required packages: `pymysql`, `requests`
- Network access to:
  - IAM Issuer URL (HTTPS)
  - FTS database host (MySQL port 3306)
- IAM admin credentials with sufficient privileges

## Database Operations

The script performs an **UPSERT** (Insert or Update) on the `t_token_provider` table:
- **Insert**: Creates a new entry if the provider doesn't exist
- **Update**: Updates `client_id` and `client_secret` if the entry already exists
  (identified by `name` and `issuer` combination)

This handles both initial setup and credential rotation scenarios.

## OAuth2 Client Details

### rucio
- **Grant Types**: `authorization_code`, `refresh_token`, `client_credentials`
- **Scopes**: `openid`, `profile`, `email`, `storage.create:/rucio`, `storage.modify:/rucio`,
              `storage.stage:/rucio`, `fts`, `offline_access`
- **Purpose**: Interactive user authentication via web browser, Token retrieval by rucio


### fts-client
- **Grant Types**: `refresh_token`, `urn:ietf:params:oauth:grant-type:token-exchange`
- **Scopes**: `storage.stage:/rucio`, `storage.modify:/rucio`, `storage.create:/rucio`,
                `fts`, `offline_access`
- **Purpose**: Token exchange for file transfer operations in FTS

## Error Handling

The script includes comprehensive error handling for:
- Missing required environment variables (exits with code 1)
- HTTP errors from IAM API (with detailed logging)
- Connection timeouts and network errors
- Database connection failures
- JSON parsing errors
- Missing credentials in API responses

## Security Notes

- Credentials are loaded from environment variables - ensure proper secret management
- Database credentials are passed directly

## Logging

The script logs to stdout with the following format:
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

Log levels:
- **INFO**: Normal operation progress
- **WARNING**: Non-fatal issues (e.g., invalid existing config)
- **ERROR**: Fatal errors with stack traces
- **DEBUG**: Detailed API interaction (when enabled)
"""

import logging
import os
import sys
from dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration loaded from environment variables.

    Attributes:
        client_id: Admin OAuth2 client ID for IAM API access
        client_secret: Admin OAuth2 client secret
        username: IAM admin username for password grant
        password: IAM admin password
        issuer_url: Base URL of the IAM instance
        config_file: Path to Rucio IDP secrets JSON file
        ftsdb_host: FTS MySQL database hostname
        ftsdb_user: FTS database username
        ftsdb_password: FTS database password
        ftsdb_name: FTS database name
    """

    client_id: str
    client_secret: str
    username: str
    password: str
    issuer_url: str
    config_file: str
    ftsdb_host: str
    ftsdb_user: str
    ftsdb_password: str
    ftsdb_name: str
    admin_scopes: str
    auth_scopes: str

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables.

        Returns:
            Config: Populated configuration object

        Raises:
            SystemExit: If IAM_ISSUER_URL is not set
        """
        issuer_url = os.environ.get("IAM_ISSUER_URL")
        if not issuer_url:
            logger.error("IAM_ISSUER_URL environment variable is required")
            sys.exit(1)

        config = cls(
            client_id=os.environ.get("TEST_ADMIN_SCOPED_CLIENT_ID", "admin-client-rw"),
            client_secret=os.environ.get("TEST_ADMIN_SCOPED_CLIENT_SECRET", "secret"),
            username=os.environ.get("ADMIN_USERNAME", "admin"),
            password=os.environ.get("ADMIN_PASSWORD", "password"),
            issuer_url=issuer_url,  # type: ignore
            config_file=os.environ.get(
                "RUCIO_IDPSECRETS_CONFIG_PATH", "/auth_config.json"
            ),
            ftsdb_host=os.environ.get("FTS_DB_HOST", "ftsdb"),
            ftsdb_user=os.environ.get("FTS_DB_USER", "fts"),
            ftsdb_password=os.environ.get("FTS_DB_PASSWORD", "fts"),
            ftsdb_name=os.environ.get("FTS_DB_NAME", "fts"),
            admin_scopes=os.environ.get(
                "ADMIN_SCOPES",
                (
                    "storage.stage:/rucio "
                    "storage.modify:/rucio "
                    "storage.create:/rucio "
                    "storage.read:/rucio "
                    "fts offline_access"
                ),
            ),
            auth_scopes=os.environ.get("AUTH_SCOPES", "openid profile email"),
        )

        logger.info("Using IAM Issuer URL: %s", config.issuer_url)
        logger.info("Config file path: %s", config.config_file)
        return config
