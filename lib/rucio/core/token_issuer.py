
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
import datetime
import os
import uuid
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from rucio.common.config import config_get, config_get_bool, config_get_int

ALLOWED_SCOPES = ["storage.read", "storage.write", "storage.modify", "storage.stage", "offline_access"]
ISSUER = config_get('client', 'rucio_host')
# TODO: decide on what should be sub for token
SUB = "rucio-service"
# kid should be some static value to encode token and put into jwks keys
KID = "EB7520023DDB48AB02BACB61F84F3D66"
# is there more alogrithm needed ?
SUPPORTED_ALGORITHMS = ["RS256"]
# should we have default audience ?
DEFAULT_AUDIENCE = ISSUER
ACCESS_TOKEN_LIFETIME = config_get_int('oidc', 'access_token_lifetime', raise_exception=False, default=21600)


# Check if OIDC token issuer is enabled in config
if config_get_bool("oidc", "rucio_token_issuer", raise_exception=False, default=False):
    # Try to get keys from environment variables first
    PRIVATE_KEY_PATH = os.getenv("OIDC_PRIVATE_KEY_PATH")
    PUBLIC_KEY_PATH = os.getenv("OIDC_PUBLIC_KEY_PATH")

    if not PRIVATE_KEY_PATH:
        # If not set in environment, try to get from config
        PRIVATE_KEY_PATH = config_get('oidc', 'oidc_private_key_path', raise_exception=True)

    if not PUBLIC_KEY_PATH:
        # If not set in environment, try to get from config
        PUBLIC_KEY_PATH = config_get('oidc', 'oidc_public_key_path', raise_exception=True)

    # Read private and public keys from the specified paths
    with open(PRIVATE_KEY_PATH, "rb") as private_key_file:
        PRIVATE_KEY_RS256 = serialization.load_pem_private_key(private_key_file.read(), password=None)

    with open(PUBLIC_KEY_PATH, "rb") as public_key_file:
        PUBLIC_KEY_RS256 = serialization.load_pem_public_key(public_key_file.read())


def openid_config_resource() -> dict[str, Any]:
    """ OpenID discovery """
    res = {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/jwks",
            "scopes_supported": ALLOWED_SCOPES,
            "response_types_supported": ["token"],
            "grant_types_supported": [],
            "claims_supported": ["sub", "aud"],
        }
    return res


def jwks() -> dict[str, list[dict[str, Any]]]:
    """Return JWKS configuration for public key discovery."""
    numbers = PUBLIC_KEY_RS256.public_numbers()
    return {
        "keys": [
            {
                "alg": "RS256",
                "kid": "RS256-1",
                "use": "sig",
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
                "e": "AQAB",  # base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
            },
        ]
    }


def _decode_token(token: str, algorithm: str = "RS256", verify_aud=False) -> dict[str, Any]:
    """
    Decodes a JWT token using the specified algorithm.

    :param token: The JWT token to decode.
    :param algorithm: The algorithm used to verify the signature (default: RS256).
    :param verify_aud: Whether to verify the audience claim (default: False).
    :return: A dictionary containing the decoded claims from the JWT.
    """
    return jwt.decode(token, PUBLIC_KEY_RS256, algorithms=[algorithm], options={"verify_aud": verify_aud})


def _create_jwt_token(
        scope: str,
        audience: Optional[str] = DEFAULT_AUDIENCE,
        algorithm: str = "RS256"
) -> str:
    """
    Creates a JWT token with the specified parameters and optional expiration offset.
    The function combines the payload creation and token encoding steps into one.

    :param sub (str): Subject (usually the user identifier).
    :param scope (str): Scope of the token.
    :param audience (Optional[str]): Audience for the token. Defaults to the system's default if not provided.
    :param algorithm (str): The algorithm to use for signing the token (default is "RS256").

    Returns: The generated JWT token.
    """
    headers = {'kid': KID}
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": SUB,
        "iss": ISSUER,
        "exp": now + datetime.timedelta(seconds=int(ACCESS_TOKEN_LIFETIME)),
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "wlcg.ver": "1.0",
        "scope": scope,
        "aud": audience,
    }
    return jwt.encode(payload, PRIVATE_KEY_RS256, algorithm=algorithm, headers=headers)


def request_access_token(
    scope: str,
    audience: Optional[str] = DEFAULT_AUDIENCE,
    algorithm: str = "RS256"
) -> dict[str, Any]:
    """
    Issues an access token.
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

    :param sub: Subject (user ID or client ID).
    :param scope: Scopes requested for the token.
    :param audience: Audience for which the token is intended.
    :param algorithm: The algorithm to use for token signing. Default is RS256.
    :return: A dictionary containing the access token response.
    """
    scopes = scope.split()
    scope_base_list = []
    for sc in scopes:
        scope_base = sc.split(":")[0]
        scope_base_list.append(scope_base)
    # Validate requested scopes against allowed scopes
    invalid_scopes = [sc for sc in scopes if sc not in ALLOWED_SCOPES]
    if invalid_scopes:
        raise ValueError(f"Invalid scopes detected: {', '.join(invalid_scopes)}")

    access_token = _create_jwt_token(scope, audience, algorithm)

    response = {
        "access_token": access_token,
        "token_type": "Bearer",  # Token type as per RFC 6749 Section 7.1
        "expires_in": ACCESS_TOKEN_LIFETIME,
    }

    return response
