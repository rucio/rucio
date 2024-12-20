
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
import hashlib
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from rucio.common.config import config_get, config_get_bool, config_get_int

ALLOWED_SCOPES = ["storage.read", "storage.write", "storage.modify", "storage.stage"]
# TODO: issuer should not contain port if standard port? use urlparse or is there better way ?
ISSUER = config_get('client', 'rucio_host')
# TODO: decide on what should be sub for token.
# currently sub is sha256 SERVICE_NAME[:16]
SERVICE_NAME = "rucio-service"
# is there more algorithm needed ?
SUPPORTED_ALGORITHMS = ["RS256"]
# should we have default audience ?
# right now its ISSUER itself
DEFAULT_AUDIENCE = ISSUER
ACCESS_TOKEN_LIFETIME = config_get_int('oidc', 'access_token_lifetime', raise_exception=False, default=21600)


# Check if OIDC token issuer is enabled in config
if config_get_bool("oidc", "rucio_token_issuer", raise_exception=False, default=False):

    PRIVATE_KEY_PATH = config_get('oidc', 'oidc_private_key_path', raise_exception=True)

    PUBLIC_KEY_PATH = config_get('oidc', 'oidc_public_key_path', raise_exception=True)

    # Read private and public keys from the specified paths
    with open(PRIVATE_KEY_PATH, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError(f"Expected an RSA private key, but got {type(private_key)}")
        PRIVATE_KEY_RS256 = private_key

    with open(PUBLIC_KEY_PATH, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError(f"Expected an RSA public key, but got {type(public_key)}")
        PUBLIC_KEY_RS256 = public_key

    # get public key bytes and compute sha256
    public_key_bytes = PUBLIC_KEY_RS256.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha256_kid = hashlib.sha256(public_key_bytes).hexdigest()
    # Use the first 12 characters of the fingerprint to create a unique KID
    KID = sha256_kid[:12]

    PUBLIC_NUMBERS = PUBLIC_KEY_RS256.public_numbers()


def _generate_stable_sub(service_name: str) -> str:
    """generate sub with hash of service_name

    :param str service_name: Service to hash for SUB
    :return str: hash sha256 first 16.
    """
    hashed_sub = hashlib.sha256(service_name.encode('utf-8')).hexdigest()
    return f"{hashed_sub[:16]}"


def openid_config_resource() -> dict[str, Any]:
    """openID Discovery.

    :return dict[str, Any]: related openID discovery info
    """
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
    """JWKS configuration for public key discovery.

    :return dict[str, list[dict[str, Any]]]: public key jwks info
    """
    return {
        "keys": [
            {
                "alg": "RS256",
                "kid": KID,
                "use": "sig",
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(PUBLIC_NUMBERS.n.to_bytes((PUBLIC_NUMBERS.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
                "e": base64.urlsafe_b64encode(PUBLIC_NUMBERS.e.to_bytes((PUBLIC_NUMBERS.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
            },
        ]
    }


def _decode_token(token: str, algorithm: str = "RS256", verify_aud: bool = False) -> dict[str, Any]:
    """
    Decodes a JWT token using the specified algorithm.

    :param token: The JWT token to decode.
    :param algorithm: The algorithm used to verify the signature (default: RS256).
    :param verify_aud: Whether to verify the audience claim (default: False).
    :return: A dictionary containing the decoded claims from the JWT.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return jwt.decode(token, PUBLIC_KEY_RS256, algorithms=[algorithm], options={"verify_aud": verify_aud})


def _create_jwt_token(
        scope: str,
        audience: str = DEFAULT_AUDIENCE,
        access_token_lifetime: int = ACCESS_TOKEN_LIFETIME,
        algorithm: str = "RS256",
) -> str:
    """
    Creates a JWT token with the specified parameters and optional expiration offset.
    The function combines the payload creation and token encoding steps into one.

    :param scope (str): Scope of the token.
    :param audience (Optional[str]): Audience for the token. Defaults to the system's default if not provided.
    :param access_token_lifetime (str): lifetime of access token. defaults to ACCESS_TOKEN_LIFETIME.
    :param algorithm (str): The algorithm to use for signing the token (default is "RS256").
    :return: The generated JWT token.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    headers = {'kid': KID}
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": _generate_stable_sub(SERVICE_NAME),
        "iss": ISSUER,
        "exp": now + datetime.timedelta(seconds=access_token_lifetime),
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
    audience: str = DEFAULT_AUDIENCE,
    access_token_lifetime: int = ACCESS_TOKEN_LIFETIME,
    algorithm: str = "RS256"
) -> dict[str, Any]:
    """
    Issues an access token.
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

    :param scope: Scopes requested for the token.
    :param audience: Audience for which the token is intended.
    :param algorithm (str): The algorithm to use for signing the token (default is "RS256").
    :param algorithm: The algorithm to use for token signing. Default is RS256.
    :return: A dictionary containing the access token response.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    scopes = scope.split()
    scope_base_list = []
    for sc in scopes:
        scope_base = sc.split(":")[0]
        scope_base_list.append(scope_base)
    # Validate requested scopes against allowed scopes
    invalid_scopes = [sc for sc in scope_base_list if sc not in ALLOWED_SCOPES]
    if invalid_scopes:
        raise ValueError(f"Invalid scopes detected: {', '.join(invalid_scopes)}")

    access_token = _create_jwt_token(scope, audience, access_token_lifetime, algorithm)

    response = {
        "access_token": access_token,
        "token_type": "Bearer",  # Token type as per RFC 6749 Section 7.1
        "expires_in": ACCESS_TOKEN_LIFETIME,
    }

    return response
