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

import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pymysql
import requests
from requests.auth import HTTPBasicAuth

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


class IAMClient:
    """Client for interacting with INDIGO IAM API.

    Provides methods for making authenticated requests to the IAM REST API,
    including OAuth2 token endpoints and client registration endpoints.

    Attributes:
        issuer_url: Base URL of the IAM instance (without trailing slash)
        session: Persistent HTTP session for connection pooling
    """

    def __init__(self, issuer_url: str):
        """Initialize IAM client.

        Args:
            issuer_url: Base URL of the IAM instance
        """
        self.issuer_url = issuer_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "IAM-Setup-Script/1.0"})
        self.session.verify = True

    def post(
        self,
        endpoint: str,
        data: Optional[dict] = None,
        json_body: Optional[dict] = None,
        auth: Optional[HTTPBasicAuth] = None,
        headers: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Make a POST request to the IAM API.

        Args:
            endpoint: API endpoint path (e.g., '/token')
            data: Form-encoded data for the request body
            json_body: JSON data for the request body
            auth: HTTP Basic authentication credentials
            headers: Additional HTTP headers

        Returns:
            Dict containing the JSON response

        Raises:
            requests.exceptions.HTTPError: On HTTP error responses
            requests.exceptions.Timeout: On request timeout
            requests.exceptions.ConnectionError: On connection failures
            json.JSONDecodeError: On invalid JSON response
        """
        url = f"{self.issuer_url}{endpoint}"
        logger.debug("POST %s", url)

        try:
            response = self.session.post(
                url, data=data, json=json_body, auth=auth, headers=headers, timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError:
            logger.error("HTTP Error %s for %s", response.status_code, url)
            logger.error("Response: %s", response.text)
            raise
        except requests.exceptions.Timeout:
            logger.error("Request timeout for %s", url)
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error for %s: %s", url, e)
            raise
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON response: %s", e)
            raise

    def put(
        self,
        endpoint: str,
        json_body: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Make a PUT request to the IAM API.

        Args:
            endpoint: API endpoint path
            json_body: JSON data for the request body
            headers: Additional HTTP headers

        Returns:
            Dict containing the JSON response, or empty dict if no response body

        Raises:
            requests.exceptions.HTTPError: On HTTP error responses
            requests.exceptions.Timeout: On request timeout
            requests.exceptions.ConnectionError: On connection failures
        """
        url = f"{self.issuer_url}{endpoint}"
        logger.debug("PUT %s", url)

        try:
            response = self.session.put(
                url, json=json_body, headers=headers, timeout=30
            )
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.HTTPError:
            logger.error("HTTP Error %s for %s", response.status_code, url)
            logger.error("Response: %s", response.text)
            raise
        except requests.exceptions.Timeout:
            logger.error("Request timeout for %s", url)
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error for %s: %s", url, e)
            raise


def ensure_config_file(config_path: Path) -> None:
    """Ensure the configuration file exists, creating it if necessary.

    Args:
        config_path: Path to the configuration file
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        config_path.write_text("{}")
        logger.info("Created new JSON config at %s", config_path)
    else:
        logger.info("Using existing JSON config: %s", config_path)


def get_admin_token(
    client: IAMClient,
    config: Config
) -> str:
    """Obtain an access token using admin client credentials.

    Uses the OAuth2 client credentials grant to obtain an access token
    with administrative privileges for IAM API operations.

    Args:
        client: IAM API client instance
        config: Configuration containing admin credentials

    Returns:
        Access token string

    Raises:
        ValueError: If access token is not present in response
        requests.exceptions.RequestException: On API request failure
    """
    logger.info("Requesting Admin Client Credentials Token...")

    token_resp = client.post(
        "/token",
        data={"grant_type": "client_credentials"},
        auth=HTTPBasicAuth(config.client_id, config.client_secret),
    )

    admin_token = token_resp.get("access_token")
    if not admin_token:
        raise ValueError("Failed to obtain admin access token")

    logger.info("Admin Token retrieved successfully")
    return admin_token



def update_admin_client(
    client: IAMClient,
    config: Config,
    admin_token: str
) -> None:
    """Update the admin client configuration to ensure correct grant types and scopes.

    Args:
        client: IAM API client instance
        config: Configuration containing admin client details
        admin_token: Access token for authentication

    Raises:
        requests.exceptions.RequestException: On API request failure
    """
    logger.info("Updating '%s' client...", config.client_id)

    update_payload = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "client_name": "iam-admin",
        "grant_types": ["client_credentials", "password"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "iam:admin.write iam:admin.read scim:write scim:read",
    }

    client.put(
        f"/iam/api/clients/{config.client_id}",
        json_body=update_payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    logger.info("'%s' updated successfully", config.client_id)


def get_user_admin_token(
    client: IAMClient,
    config: Config
) -> str:
    """Obtain an access token using admin user password credentials.

    Uses the OAuth2 password grant to obtain an access token with admin user privileges.
    This is required by IAM for registering clients with the client_credentials
    grant type.
    Ref: https://indigo-iam.github.io/v/v1.12.1/blog/2024/03/25/iam-v1.8.4/

    Args:
        client: IAM API client instance
        config: Configuration containing admin user credentials

    Returns:
        Access token string

    Raises:
        ValueError: If access token is not present in response
        requests.exceptions.RequestException: On API request failure
    """
    logger.info("Requesting Admin User Password Token...")

    token_resp = client.post(
        "/token",
        data={
            "grant_type": "password",
            "username": config.username,
            "password": config.password,
        },
        auth=HTTPBasicAuth(config.client_id, config.client_secret),
    )

    user_token = token_resp.get("access_token")
    if not user_token:
        raise ValueError("Failed to obtain user admin access token")

    logger.info("User Admin Token retrieved successfully")
    return user_token


def register_rucio_client(
    client: IAMClient,
    user_admin_token: str,
    config: Config
) -> tuple[str, str]:
    """Register the Rucio client required by rucio.
    Registers an OAuth2 client that supports the Authorization Code Flow
    for web-based user authentication with Rucio.
    Registers an OAuth2 client that supports the Client Credentials Flow
    for machine-to-machine storage operations with XRootD endpoints and FTS.

    Args:
        client: IAM API client instance
        user_admin_token: User admin access token for authentication

    Returns:
        Tuple of (client_id, client_secret)

    Raises:
        ValueError: If client credentials are missing from response
        requests.exceptions.RequestException: On API request failure
    """
    logger.info("Registering 'rucio-admin' client...")

    registration_payload = {
        "client_name": "rucio",
        "scope": f"{config.auth_scopes} {config.admin_scopes}",
        "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
        "redirect_uris": [
            "https://rucio/auth/oidc_token",
            "https://rucio/auth/oidc_code",
        ],
        "token_endpoint_auth_method": "client_secret_basic",
        "response_types": ["code"],
    }

    response = client.post(
        "/iam/api/client-registration",
        json_body=registration_payload,
        headers={"Authorization": f"Bearer {user_admin_token}"},
    )

    client_id = response.get("client_id")
    client_secret = response.get("client_secret")

    if not client_id or not client_secret:
        raise ValueError("Failed to register rucio-admin - missing credentials")

    logger.info("Rucio admin client registered successfully (ID: %s)", client_id)
    return client_id, client_secret


def update_config_file(
    config_path: Path,
    issuer_url: str,
    rucio_client_id: str,
    rucio_client_secret: str,
    scim_client_id: str,
    scim_client_secret: str,
) -> None:
    """Update the Rucio IDP secrets JSON configuration file.

    Creates or updates the JSON file with OAuth2 client credentials and IAM settings.
    Preserves existing configuration keys not related to 'indigoiam'.

    Args:
        config_path: Path to the configuration file
        issuer_url: IAM issuer URL
        rucio_client_id: Rucio auth client ID
        rucio_client_secret: Rucio auth client secret
        scim_client_id: Rucio admin (SCIM) client ID
        scim_client_secret: Rucio admin (SCIM) client secret

    Raises:
        OSError: On file I/O errors
        json.JSONDecodeError: On invalid existing JSON
    """
    logger.info("Updating JSON configuration...")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except json.JSONDecodeError:
        logger.warning("Existing config file is invalid JSON, starting fresh")
        cfg = {}

    cfg["indigoiam"] = {
        "client_id": rucio_client_id,
        "client_secret": rucio_client_secret,
        "issuer": issuer_url if issuer_url.endswith("/") else f"{issuer_url}/",
        "redirect_uris": [
            "https://rucio/auth/oidc_token",
            "https://rucio/auth/oidc_code",
        ],
        "SCIM": {
            "client_id": scim_client_id,
            "client_secret": scim_client_secret,
        },
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    logger.info("JSON configuration updated successfully at %s", config_path)


def register_fts_client(
    client: IAMClient,
    admin_token: str,
    config: Config
) -> tuple[str, str]:
    """Register the FTS client for token exchange and refresh operations.

    Registers an OAuth2 client that supports Token Exchange and Refresh Token grants
    for FTS file transfer operations.

    Args:
        client: IAM API client instance
        admin_token: Access token for authentication
        fts_scopes: Space-separated list of OAuth2 scopes required by FTS

    Returns:
        Tuple of (client_id, client_secret)

    Raises:
        ValueError: If client credentials are missing from response
        requests.exceptions.RequestException: On API request failure
    """
    logger.info("Registering 'fts-client' for token exchange...")

    registration_payload = {
        "client_name": "fts-client",
        "scope": f"{config.admin_scopes}",
        "grant_types": [
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "token_endpoint_auth_method": "client_secret_basic",
        "response_types": [],
        # audience might not be needed, test
        # "audience": ["fts"],
    }

    response = client.post(
        "/iam/api/client-registration",
        json_body=registration_payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    client_id = response.get("client_id")
    client_secret = response.get("client_secret")

    if not client_id or not client_secret:
        raise ValueError("Failed to register fts-client - missing credentials")

    logger.info("FTS client registered successfully (ID: %s)", client_id)
    return client_id, client_secret



def update_fts_database_token_provider(
    config: Config,
    fts_client_id: str,
    fts_client_secret: str
) -> None:
    """Update FTS database with OAuth2 token provider credentials.

    Performs an UPSERT operation on the t_token_provider table to insert or update
    the OAuth2 client credentials used by FTS for token exchange. The unique key
    is the combination of (name, issuer).

    Args:
        config: Configuration containing database connection details
        fts_client_id: FTS OAuth2 client ID
        fts_client_secret: FTS OAuth2 client secret

    Raises:
        pymysql.err.Error: On database errors
        Exception: On unexpected errors during database operations
    """
    logger.info(
        "Connecting to FTS database (%s) to update t_token_provider...",
        config.ftsdb_host,
    )

    provider_name = "indigoiam"
    required_submission_scope = "fts"
    issuer_url = config.issuer_url

    conn = None
    try:
        # Establish connection to the database
        conn = pymysql.connect(
            host=config.ftsdb_host,
            user=config.ftsdb_user,
            password=config.ftsdb_password,
            database=config.ftsdb_name,
        )

        with conn.cursor() as cursor:
            sql_upsert = """
            INSERT INTO t_token_provider (
                name,
                issuer,
                client_id,
                client_secret,
                required_submission_scope
            )
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                client_id = VALUES(client_id),
                client_secret = VALUES(client_secret),
                required_submission_scope = VALUES(required_submission_scope)
            """


            cursor.execute(
                sql_upsert,
                (
                    provider_name,
                    issuer_url,
                    fts_client_id,
                    fts_client_secret,
                    required_submission_scope,
                ),
            )

            rows_affected = cursor.rowcount
            conn.commit()

            # rowcount: 1 = INSERT, 2 = UPDATE with changes, 0 = UPDATE without changes
            logger.info(
                "Successfully performed UPSERT on t_token_provider for '%s'." \
                "Rows affected: %d",
                provider_name,
                rows_affected,
            )

    except pymysql.err.Error as e:
        logger.error("FTS Database error: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected error during database update: %s", e)
        raise

    finally:
        if conn and conn.open:
            conn.close()
            logger.debug("Database connection closed")
