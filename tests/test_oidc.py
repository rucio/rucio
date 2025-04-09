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

import json
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

from rucio.common.exception import CannotAuthenticate, CannotAuthorize, IdentityError
from rucio.common.types import InternalAccount
from rucio.core.account import add_account, del_account
from rucio.core.authentication import redirect_auth_oidc
from rucio.core.config import remove_option as config_remove
from rucio.core.config import set as config_set
from rucio.core.identity import add_account_identity
from rucio.core.oidc import IDPSecretLoad, get_auth_oidc, get_token_oidc, request_token, validate_jwt, validate_token
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountType, IdentityType
from rucio.db.sqla.session import get_session
from rucio.tests.common import account_name_generator

if TYPE_CHECKING:
    from collections.abc import Iterator


def get_oauth_session_row(account, state=None, session=None):
    stmt = select(
        models.OAuthRequest
    ).where(
        models.OAuthRequest.account == account
    )
    if state:
        stmt = stmt.where(
            models.OAuthRequest.state == state
        )
    return session.execute(stmt).scalars().all()


def get_token_row(access_token, account=None, session=None) -> models.Token:
    stmt = select(
        models.Token
    ).where(
        models.Token.token == access_token
    )
    token = session.execute(stmt).scalar_one_or_none()
    if account and token:
        assert token.account == account
    return token


# Sample IDP secret mock data
mock_idpsecrets = {
    "def": {
        "user_auth_client": [
            {
                "issuer": "https://mock-oidc-provider",
                "client_id": "mock-client-id",
                "client_secret": "secret",
                "redirect_uris": "https://redirect.example.com",
                "issuer_nickname": "example_issuer"
            }
        ],
        "client_credential_client": {
            "client_id": "client456",
            "client_secret": "secret456",
            "issuer": "https://mock-oidc-provider"
        }
    }
}


@pytest.fixture
def idp_secrets_mock(request) -> "Iterator[str]":
    """
    Fixture that sets up a temporary JSON file containing IDP secrets and sets
    the IDP_SECRETS_FILE environment variable to point to this file.

    This ensures tests use an isolated, in-memory secret configuration that
    is cleaned up after the fixture exits.
    """
    secrets = request.param

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode="w", delete=True, suffix=".json") as tmp_file:
        json.dump(secrets, tmp_file)
        tmp_file.flush()
        tmp_file_name = tmp_file.name
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("IDP_SECRETS_FILE", tmp_file_name)
            yield mp


@pytest.fixture
def get_jwks_content(generate_rsa_keypair):
    """Mock JWKS content using the generated RSA public key."""
    _, public_key, _, _ = generate_rsa_keypair

    jwk = {"keys": [
        {
            "kid": "test-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            **RSAAlgorithm.to_jwk(public_key, as_dict=True)
        }
        ]
    }
    return jwk


@pytest.fixture
def get_discovery_metadata():
    """Mock OIDC discovery metadata."""
    return {
        "issuer": "https://mock-oidc-provider",
        "jwks_uri": "https://mock-oidc-provider/.well-known/jwks.json",
        "token_endpoint": "https://mock-oidc-provider/token",
        "authorization_endpoint": "https://mock-oidc-provider/authorize",
    }


@pytest.fixture
def generate_rsa_keypair():
    """Generate an RSA keypair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_key, public_key, private_pem, public_pem


@pytest.fixture
def encode_jwt_id_token_with_argument(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `aud` and `scope`."""
    def _generate_jwt(sub, nonce):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": sub,
            "name": "John Doe",
            "jti": str(uuid.uuid4()),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "nbf": datetime.utcnow(),
            "iss": "https://mock-oidc-provider",
            "aud": "mock-client-id",
            "nonce": nonce,
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt


@pytest.fixture
def encode_jwt_with_argument(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `sub`, `aud` and `scope`."""
    def _generate_jwt(sub, aud, scope):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": sub,
            "name": "John Doe",
            "jti": str(uuid.uuid4()),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "nbf": datetime.utcnow(),
            "iss": "https://mock-oidc-provider",
            "aud": aud,
            "scope": scope
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt


@pytest.fixture
def encode_jwt_refresh_token(generate_rsa_keypair):
    """Generate a refresh JWT using the mock JWKS private key."""
    private_key, _, _, _ = generate_rsa_keypair

    payload = {
        "sub": "1234567890",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=30),
        "nbf": datetime.utcnow(),
        "iss": "https://mock-oidc-provider",
        "aud": "rucio"
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
    return token


@pytest.fixture
def setup_account_and_session():
    # Set up the account and session
    usr = account_name_generator()
    sub = str(account_name_generator())
    account = InternalAccount(usr)
    db_session = get_session()

    add_account(account, AccountType.USER, 'rucio@email.com', session=db_session)
    add_account_identity(f'SUB={sub}, ISS=https://mock-oidc-provider', IdentityType.OIDC, account, 'rucio@email.com', session=db_session)
    db_session.commit()

    # Yield the necessary objects to the test function
    yield account, sub, db_session

    # Teardown: Clean up the session, account, and configuration
    config_remove(section='oidc', option='extra_access_token_scope', session=db_session)
    del_account(account, session=db_session)
    db_session.remove()


def get_idp_auth_params(auth_url, session):
    urlparsed = urlparse(auth_url)
    idp_auth_url = redirect_auth_oidc(urlparsed.query, session=session)
    idp_urlparsed = urlparse(idp_auth_url)
    return parse_qs(idp_urlparsed.query)


@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_vo_user_auth_config(idp_secrets_mock):
    config = IDPSecretLoad()
    result = config.get_vo_user_auth_config(vo="def")
    assert result["client_id"] == "mock-client-id"
    assert result["issuer"] == "https://mock-oidc-provider"


@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_client_credential_client(idp_secrets_mock):
    config = IDPSecretLoad()
    result = config.get_client_credential_client(vo="def")
    assert result["client_id"] == "client456"
    assert result["issuer"] == "https://mock-oidc-provider"


@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_config_from_clientid_issuer(idp_secrets_mock):
    config = IDPSecretLoad()
    result = config.get_config_from_clientid_issuer("mock-client-id", "https://mock-oidc-provider")
    assert result["client_id"] == "mock-client-id"
    assert result["issuer"] == "https://mock-oidc-provider"


@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_is_valid_issuer(idp_secrets_mock):
    config = IDPSecretLoad()
    result = config.is_valid_issuer(issuer_url="https://mock-oidc-provider", vo='def')
    assert result == True


def test_validate_token_success(encode_jwt_id_token_with_argument, get_discovery_metadata, get_jwks_content):
    sub = str(account_name_generator())
    nonce = "known"
    token = encode_jwt_id_token_with_argument(sub, nonce)
    """Test successful token validation."""
    # Patching get_discovery_metadata and get_jwks_content using unittest.mock.patch
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        # Call the function being tested
        decoded_token = validate_token(
            token=token,
            issuer_url=get_discovery_metadata["issuer"],
            audience="mock-client-id",
            token_type="id_token",
            nonce=nonce
        )

        # Assertions based on expected decoded values
        assert decoded_token["sub"] == sub
        assert decoded_token["iss"] == get_discovery_metadata["issuer"]

        # Verify that get_discovery_metadata and get_jwks_content were called
        mock_get_jwks_content.assert_called_once()


def test_validate_token_invalid_nonce(encode_jwt_id_token_with_argument, get_jwks_content):
    """Test failure due to incorrect nonce."""
    sub = str(account_name_generator())
    nonce = "known"
    token = encode_jwt_id_token_with_argument(sub,  nonce)
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate, match="Invalid nonce in ID token."):
            validate_token(
                token=token,
                issuer_url="https://mock-oidc-provider",
                audience="mock-client-id",
                token_type="id_token",
                nonce="wrong-nonce"
            )


def test_validate_token_extra_acess_token_scope(encode_jwt_with_argument, get_jwks_content, setup_account_and_session):
    """Test failure due to incorrect nonce."""
    account, sub, db_session = setup_account_and_session
    config_set(section='oidc', option='extra_access_token_scope', value='test', session = db_session)
    aud = "rucio"
    scope = 'test'
    token = encode_jwt_with_argument(sub, aud, scope)


    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        validate_token(
            token=token,
            issuer_url="https://mock-oidc-provider",
            audience=aud,
            token_type="access_token",
            scopes=[scope]
        )
        # Verify that get_discovery_metadata and get_jwks_content were called
        mock_get_jwks_content.assert_called_once()
    config_remove(section='oidc', option='extra_access_token_scope', session = db_session)


def test_validate_token_extra_invalid_acess_token_scope(encode_jwt_with_argument, get_jwks_content, setup_account_and_session):
    account, sub, db_session = setup_account_and_session
    config_set(section='oidc', option='extra_access_token_scope', value='test', session=db_session)
    aud = "rucio"
    scope = 'random'
    token = encode_jwt_with_argument(sub, aud, scope)
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate):
            validate_token(
                token=token,
                issuer_url="https://mock-oidc-provider",
                audience="mock-client-id",
                token_type="access_token",
                scopes= [scope]
            )
    config_remove(section='oidc', option='extra_access_token_scope', session=db_session)


@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
@pytest.mark.parametrize("audience, scope", [
    ("https://mysourcerse.com", "storage.read:/mydir"),
    ("https://mydestrse.com", "storage.modify:/mydir storage.read:/mydir"),
    ("https://mysourcerse.com", "storage.read:/mydir/myfile.txt")
])
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_request_token_success(mock_post, mock_get_discovery_metadata, idp_secrets_mock, encode_jwt_with_argument, audience, scope, get_discovery_metadata):
    sub = str(account_name_generator())
    mock_token = encode_jwt_with_argument(sub, audience, scope)
    # Prepare mock response
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": mock_token}  # Mock the response to return the token
    # Mock the requests.post to return the mock_response
    mock_post.return_value = mock_response

    mock_get_discovery_metadata.return_value = get_discovery_metadata

    result = request_token(scope=scope, audience=audience, vo="def", use_cache=False)
    # Assertions to ensure everything works as expected
    mock_post.assert_called_once()  # Ensure the post request was made
    mock_post.assert_called_with(
        url=get_discovery_metadata["token_endpoint"],
        auth=(mock_idpsecrets["def"]["client_credential_client"]["client_id"], mock_idpsecrets["def"]["client_credential_client"]["client_secret"]),
        data={
            'grant_type': 'client_credentials',
            'scope': scope,
            'audience': audience
        },
        timeout=10
    )
    assert result == mock_token
    # Decode the JWT token and validate the claims
    decoded_token = jwt.decode(result, options={"verify_signature": False})
    # Validate the claims
    assert decoded_token["aud"] == audience
    assert decoded_token["scope"] == scope


@patch("rucio.core.oidc.get_discovery_metadata")
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_auth_oidc(mock_get_discovery_metadata, idp_secrets_mock, get_discovery_metadata, setup_account_and_session):
    account, _, db_session = setup_account_and_session

    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }

    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    redirect_url = mock_idpsecrets["def"]["user_auth_client"][0]["redirect_uris"]
    assert f"{redirect_url}/auth/oidc_redirect?" in auth_url and '_polling' not in auth_url

    idp_params = get_idp_auth_params(auth_url, db_session)
    assert 'state' in idp_params
    assert 'nonce' in idp_params
    assert idp_params["audience"][0] in kwargs["audience"]
    assert idp_params["client_id"][0] in mock_idpsecrets["def"]["user_auth_client"][0]["client_id"]
    assert 'code' in idp_params["response_type"][0]

    # Test polling mode
    kwargs["polling"] = True
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)
    assert f"{redirect_url}/auth/oidc_redirect?" in auth_url and '_polling' in auth_url

    # Test modified auth_scope
    kwargs["polling"] = False
    kwargs["auth_scope"] = "openid profile extra_scope"
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)
    idp_params = get_idp_auth_params(auth_url, db_session)
    assert kwargs["auth_scope"] in idp_params["scope"][0]

    # Test unknown identity
    new_account = InternalAccount('random')
    auth_url = get_auth_oidc(new_account, session=db_session, **kwargs)
    assert auth_url is None


@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_token_oidc_success(mock_post, mock_get_discovery_metadata, idp_secrets_mock, encode_jwt_id_token_with_argument, encode_jwt_with_argument, get_discovery_metadata, get_jwks_content, setup_account_and_session):
    account, sub, db_session = setup_account_and_session

    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }

    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, nonce = idp_params["state"][0], idp_params["nonce"][0]
    # created id_token with same nonce
    id_token = encode_jwt_id_token_with_argument(sub, nonce)
    access_token =  encode_jwt_with_argument(sub, "rucio", "openid profile")
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": access_token, "id_token": id_token, "expires_in": 3600, "scope": "test"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=test_code&state={state}"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        result = get_token_oidc(auth_query_string, session=db_session)
        assert 'fetchcode' in result
        db_token = get_token_row(access_token, account=account, session=db_session)
        assert db_token
        assert db_token.token == access_token
        assert db_token.refresh is False
        assert db_token.account == account
        assert db_token.identity == f'SUB={sub}, ISS=https://mock-oidc-provider'
        assert db_token.audience == 'rucio'


    # wrong state validation
    auth_query_string = f"code=test_code&state=wrongstate"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate):
            get_token_oidc(auth_query_string, session=db_session)


@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_token_oidc_wrong_code(mock_post, mock_get_discovery_metadata, idp_secrets_mock, encode_jwt_id_token_with_argument, encode_jwt_with_argument, get_discovery_metadata, get_jwks_content, setup_account_and_session):
    account, sub, db_session = setup_account_and_session

    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }

    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, _ = idp_params["state"][0], idp_params["nonce"][0]
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("400 Client Error: Bad Request for url")
    mock_response.json.return_value = {"error": "invalid_grant", "error_description": "Invalid authorization code"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=wrongcode&state={state}"

    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthorize, match="Failed to exchange code for token"):
            get_token_oidc(auth_query_string, session=db_session)


@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_token_oidc_polling_success(mock_post, mock_get_discovery_metadata, idp_secrets_mock, encode_jwt_id_token_with_argument, encode_jwt_with_argument, get_discovery_metadata, get_jwks_content, setup_account_and_session):
    account, sub, db_session = setup_account_and_session

    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',
        'issuer': 'https://mock-oidc-provider',
        'polling': True,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }

    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, nonce = idp_params["state"][0], idp_params["nonce"][0]
    # created id_token with same nonce
    id_token = encode_jwt_id_token_with_argument(sub, nonce)
    access_token =  encode_jwt_with_argument(sub, "rucio", "openid profile")
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": access_token, "id_token": id_token, "expires_in": 3600, "scope": "test"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=test_code&state={state}"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        result = get_token_oidc(auth_query_string, session=db_session)
        assert 'polling' in result
        assert result['polling']


@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_get_token_oidc_with_refresh_token(mock_post, mock_get_discovery_metadata, idp_secrets_mock, encode_jwt_id_token_with_argument, encode_jwt_with_argument, encode_jwt_refresh_token, get_discovery_metadata, get_jwks_content, setup_account_and_session):
    account, sub, db_session = setup_account_and_session

    kwargs = {
        'auth_scope': 'openid profile offline_access',
        'audience': 'rucio',
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }
    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, nonce = idp_params["state"][0], idp_params["nonce"][0]
    # created id_token with same nonce
    id_token = encode_jwt_id_token_with_argument(sub, nonce)
    access_token =  encode_jwt_with_argument(sub, "rucio", "openid profile")
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {"refresh_token": encode_jwt_refresh_token, "access_token": access_token, "id_token": id_token, "expires_in": 3600, "scope": "test"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=test_code&state={state}"
    print(auth_query_string)
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        get_token_oidc(auth_query_string, session=db_session)
        db_token = get_token_row(access_token, account=account, session=db_session)
        assert db_token
        assert db_token.refresh_token == encode_jwt_refresh_token


@patch("rucio.core.oidc.get_discovery_metadata")
@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets], indirect=True)
def test_validate_jwt_sucess(mock_get_discovery_metadata, encode_jwt_with_argument, idp_secrets_mock, get_discovery_metadata, get_jwks_content, setup_account_and_session):
    account, sub, db_session = setup_account_and_session

    mock_get_discovery_metadata.return_value = get_discovery_metadata
    mock_token = encode_jwt_with_argument(sub, 'rucio', 'openid profile test')
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        validate_jwt(mock_token, session=db_session)
        db_token = get_token_row(mock_token, account=account, session=db_session)
        assert db_token.token == mock_token

    # test with random audience
    mock_token = encode_jwt_with_argument(sub, 'random', 'openid profile test')
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate, match="Invalid access_token: Audience doesn't match"):
            validate_jwt(mock_token, session=db_session)
            db_token = get_token_row(mock_token, account=account, session=db_session)
            assert db_token.token == mock_token

    # test with external token with missing required scope
    mock_token = encode_jwt_with_argument(sub, 'rucio', 'random')
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate, match="doesn't have required scope"):
            validate_jwt(mock_token, session=db_session)
            db_token = get_token_row(mock_token, account=account, session=db_session)
            assert db_token.token == mock_token

    # non existent account i.e. with random sub and corresponding account.
    mock_token = encode_jwt_with_argument('random','rucio', 'openid profile test')
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(IdentityError):
            validate_jwt(mock_token, session=db_session)
    db_token = get_token_row(mock_token, account=account, session=db_session)
    assert not db_token



# Sample IDP secret mock data
mock_idpsecrets_multi_issuer = {
    "def": {
        "user_auth_client": [
            {
                "issuer": "https://mock-oidc-provider",
                "client_id": "mock-client-id",
                "client_secret": "secret",
                "redirect_uris": "https://redirect.example.com",
                "issuer_nickname": "example_issuer"
            },
            {
                "issuer": "https://mock-oidc-provider2",
                "client_id": "mock-client-id2",
                "client_secret": "secret2",
                "redirect_uris": "https://redirect.example.com",
                "issuer_nickname": "example_issuer2"
            }
        ],
        "client_credential_client": {
            "client_id": "client456",
            "client_secret": "secret456",
            "issuer": "https://mock-oidc-provider"
        }
    }
}


@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets_multi_issuer], indirect=True)
def test_get_vo_user_auth_config_multi(idp_secrets_mock):
    config = IDPSecretLoad()
    result = config.get_vo_user_auth_config(issuer_nickname="example_issuer2")
    assert result["client_id"] == "mock-client-id2"
    assert result["issuer"] == "https://mock-oidc-provider2"


@pytest.mark.parametrize('idp_secrets_mock', [mock_idpsecrets_multi_issuer], indirect=True)
def test_get_client_credential_client_multi(idp_secrets_mock):
    config = IDPSecretLoad()
    result = config.get_client_credential_client()
    assert result["client_id"] == "client456"
    assert result["issuer"] == "https://mock-oidc-provider"


mock_idpsecrets_multi_vo = {
    "def": {
        "user_auth_client": [
            {
                "issuer": "https://mock-oidc-provider",
                "client_id": "mock-client-id",
                "client_secret": "secret",
                "redirect_uris": "https://redirect.example.com",
                "issuer_nickname": "example_issuer"
            },
        ],
        "client_credential_client": {
            "client_id": "client456",
            "client_secret": "secret456",
            "issuer": "https://mock-oidc-provider"
        }
    },
    "new": {
        "user_auth_client": [
            {
                "issuer": "https://mock-oidc-provider",
                "client_id": "mock-client-id",
                "client_secret": "secret",
                "redirect_uris": "https://redirect.example.com",
                "issuer_nickname": "example_issuer2"
            },
        ],
        "client_credential_client": {
            "client_id": "client4562",
            "client_secret": "secret4562",
            "issuer": "https://mock-oidc-provider2"
        }
    }
}


@pytest.fixture
def encode_jwt_id_token_with_argument_iss(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `aud` and `scope`."""
    def _generate_jwt(sub, aud, nonce, iss):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": sub,
            "name": "John Doe",
            "jti": str(uuid.uuid4()),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "nbf": datetime.utcnow(),
            "iss": iss,
            "aud": aud,
            "nonce": nonce,
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt


@pytest.fixture
def encode_jwt_with_argument_iss(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `sub`, `aud` and `scope`."""
    def _generate_jwt(sub, aud, scope, iss):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": sub,
            "name": "John Doe",
            "jti": str(uuid.uuid4()),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "nbf": datetime.utcnow(),
            "iss": iss,
            "aud": aud,
            "scope": scope
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt