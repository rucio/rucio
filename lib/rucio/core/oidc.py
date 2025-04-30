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

import hashlib
import json
import logging
import os
import traceback
import uuid
from datetime import datetime, timedelta
from math import floor
from typing import TYPE_CHECKING, Any, Final, Literal, Optional, Union, cast
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from dogpile.cache.api import NoValue
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import delete, null, or_, select, update
from sqlalchemy.sql.expression import true

from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get, config_get_bool, config_get_int, config_get_list
from rucio.common.exception import CannotAuthenticate, CannotAuthorize, RucioException
from rucio.common.stopwatch import Stopwatch
from rucio.common.utils import build_url, chunks, val_to_space_sep_str
from rucio.core.account import account_exists
from rucio.core.identity import exist_identity_account, get_default_account
from rucio.core.monitor import MetricManager
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, TokenValidationDict

# The WLCG Common JWT Profile dictates that the lifetime of access and ID tokens
# should range from five minutes to six hours.
TOKEN_MIN_LIFETIME: Final = config_get_int('oidc', 'token_min_lifetime', default=300)
TOKEN_MAX_LIFETIME: Final = config_get_int('oidc', 'token_max_lifetime', default=21600)

REGION: Final = MemcacheRegion(expiration_time=TOKEN_MAX_LIFETIME)
METRICS: Final = MetricManager(module=__name__)

# issuer discovery cache lifetime. The recommended value can vary for each issuer
DISCOVERY_CACHE_LIFETIME: Final = config_get_int('oidc', 'discovery_cache_lifetime', False, 86400)
DISCOVERY_CACHE_REGION: Final = MemcacheRegion(expiration_time=DISCOVERY_CACHE_LIFETIME)

# private/protected file containing Rucio Client secrets known to the Identity Provider as well
IDPSECRETS = config_get('oidc', 'idpsecrets', False)

# expected audience for access token
EXPECTED_OIDC_AUDIENCE = config_get('oidc', 'expected_audience', False, 'rucio')

# The 'openid' scope is always required for an ID token to be issued.
# 'profile' is added as required for extra scope
DEFAULT_ID_TOKEN_SCOPES = ['openid', 'profile']
# Extra scopes for id token.
ID_TOKEN_EXTRA_SCOPES: list = config_get_list('oidc', 'id_token_extra_scopes', False, [])
# Corresponding claim that needs to there for ID_TOKEN_EXTRA_SCOPES
ID_TOKEN_EXTRA_CLAIMS: list = config_get_list('oidc', 'id_token_extra_claims', False, [])
# extra scope to ask for in access token.
# some issuer wants to have extra scope for RP to validate against.
EXTRA_OIDC_ACCESS_TOKEN_SCOPE: list = config_get_list('oidc', 'extra_access_token_scope', False, default='')  # type: ignore
REFRESH_LIFETIME_H = config_get_int('oidc', 'default_jwt_refresh_lifetime', False, 96)

# Allow 2 mins of leeway in case Rucio and IdP server clocks are not perfectly synchronized
# this affects the token issued time (a token could be issued in the future if IdP clock is ahead)
LEEWAY_SECS = 120


# TO-DO permission layer: if scope == 'wlcg.groups'

class IDPSecretLoad:
    """
    Class to load and manage Identity Provider secrets from a JSON configuration file.

    :param config_file: Path to the JSON configuration file.
    """

    def __init__(self):
        """Initialize with a JSON configuration file."""
        self.config_file = os.getenv("IDP_SECRETS_FILE", IDPSECRETS)
        self._config = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load and validate the configuration file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self._config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise ValueError(f"Error loading '{self.config_file}': {exc}")

        self._validate_config()

    def _validate_config(self) -> None:
        """
        Validate the configuration format.

        :raises: ValueError if the configuration is invalid.
        """
        if not self._config:
            raise ValueError("Configuration is empty or invalid.")

        required_keys = {"client_id", "client_secret", "issuer"}

        for vo, details in self._config.items():
            if not isinstance(details, dict):
                raise ValueError(f"VO '{vo}' must have a dictionary configuration.")

            for client_type in ["user_auth_client", "client_credential_client"]:
                clients = details.get(client_type, None)
                if not clients:
                    continue
                if not isinstance(clients, list) or not all(isinstance(entry, dict) for entry in clients):
                    raise ValueError(f"VO '{vo}' {client_type} must be a list of dictionaries.")

                for entry in clients:
                    if not required_keys.issubset(entry):
                        raise ValueError(f"VO '{vo}' {client_type} must have 'issuer', 'client_id', and 'client_secret'.")

                    if client_type == "user_auth_client":
                        if "redirect_uris" not in entry:
                            raise ValueError(f"VO '{vo}' user_auth_client must have 'redirect_uris' ")

                if client_type == "client_credential_client" and len(clients) > 1:
                    raise ValueError(f"only one client is permitted for client_credential_client for now.")

                if len(clients) > 1:
                    for entry in clients:
                        if "issuer_nickname" not in entry or not isinstance(entry["issuer_nickname"], str):
                            raise ValueError(f"Each entry in '{client_type}' for VO '{vo}' must have a valid 'issuer_nickname' when multiple clients exist.")


    def get_vo_clients_config(
        self,
        client_type: Literal["user_auth_client", "client_credential_client"],
        vo: str = "def",
        issuer_nickname: Optional[str] = None
    ) -> dict[str, str]:
        """
        Retrieve the issuer configuration for a VO.

        :param client_type: Type of client configuration to retrieve.
        :param vo: Virtual Organization identifier.
        :param issuer_nickname: Optional issuer nickname.
        :returns: Issuer configuration dictionary.
        :raises: ValueError if VO or issuer nickname is not found.
        """
        config = self._config.get(vo)
        if not config:
            raise ValueError(f"VO '{vo}' not found in the configuration.")
        if client_type not in config:
            raise ValueError(f"Client type '{client_type}' not found for VO '{vo}'.")

        client_config_list = config[client_type]
        if len(client_config_list) == 1:
            return client_config_list[0]

        if len(client_config_list) > 1 and not issuer_nickname:
            raise ValueError("Issuer nickname is required since server has multiple issuers configured.")

        for issuer_config in client_config_list:
            if issuer_config.get("issuer_nickname") == issuer_nickname:
                return issuer_config

        raise ValueError(f"Issuer nickname '{issuer_nickname}' not found for client type '{client_type}' in VO '{vo}'.")

    def get_config_from_clientid_issuer(self, client_id: str, issuer: str) -> dict[str, str]:
        """
        Retrieve configuration based on client ID and issuer.

        :param client_id: Client ID.
        :param issuer: Issuer URL.
        :returns: Configuration dictionary.
        """
        config = self._config
        all_config = list(config.values())
        for vo_config in all_config:
            user_auth_config = vo_config["user_auth_client"]
            for issuer_auth_config in user_auth_config:
                if issuer_auth_config["client_id"] == client_id and issuer_auth_config["issuer"].rstrip('/') == issuer.rstrip('/'):
                    return issuer_auth_config
        raise ValueError(f"Client_ID '{client_id}' not found for issuer '{issuer}'.")

    def is_valid_issuer(self, issuer_url: str, vo: str = "def", issuer_nickname: Optional[str] = None) -> bool:
        """
        Check if the given issuer URL matches the VO's configured issuer.

        :param issuer_url: Issuer URL.
        :param vo: Virtual Organization identifier.
        :param issuer_nickname: Optional issuer nickname.
        :returns: True if the issuer URL is valid, False otherwise.
        """
        return self.get_vo_clients_config(client_type="user_auth_client", vo=vo, issuer_nickname=issuer_nickname).get("issuer") == issuer_url

@METRICS.time_it
def _token_cache_get(
    key: str,
    min_lifetime: int = TOKEN_MIN_LIFETIME,
) -> Optional[str]:
    """
    Retrieve a token from the cache.

    :param key: Cache key.
    :param min_lifetime: Minimum lifetime of the token in seconds.
    :returns: Token string if valid, None otherwise.
    """
    value = REGION.get(key)
    if isinstance(value, NoValue):
        METRICS.counter('token_cache.miss').inc()
        return None

    if isinstance(value, str):
        try:
            payload = jwt.decode(value, options={"verify_signature": False})
        except Exception:
            METRICS.counter('token_cache.invalid').inc()
            return None
    else:
        METRICS.counter('token_cache.invalid').inc()
        return None

    now = datetime.utcnow().timestamp()
    expiration = payload.get('exp', 0)    # type: ignore
    if now + min_lifetime > expiration:
        METRICS.counter('token_cache.expired').inc()
        return None

    METRICS.counter('token_cache.hit').inc()
    return value


def get_discovery_metadata(issuer_url: str) -> dict[str, Any]:
    """
    Retrieve the discovery metadata for an issuer.

    :param issuer_url: Issuer URL.
    :returns: Discovery metadata dictionary.
    """
    # Check if the JWKS content is already cached
    cache_key = f"discovery_metadata_{issuer_url}"
    cached_discovery = DISCOVERY_CACHE_REGION.get(cache_key, None)
    if cached_discovery:
        if isinstance(cached_discovery, dict):
            return cached_discovery
        else:
            pass
    discovery_url = f"{issuer_url}/.well-known/openid-configuration"
    response = requests.get(discovery_url, timeout=10)
    response.raise_for_status()
    metadata = response.json()
    DISCOVERY_CACHE_REGION.set(cache_key, metadata)
    return metadata


def get_jwks_content(issuer_url: str) -> dict[str, Any]:
    """
    Discover the JWKS content from the issuer's metadata and cache the response.

    :param issuer_url: The issuer's base URL (e.g., https://example.com).
    :return: The JWKS content.
    """
    # Check if the JWKS content is already cached
    cache_key = f"jwks_content_{issuer_url}"
    cached_jwks = DISCOVERY_CACHE_REGION.get(cache_key, None)

    if cached_jwks:
        if isinstance(cached_jwks, dict):
            return cached_jwks
        else:
            pass
    metadata = get_discovery_metadata(issuer_url=issuer_url)

    # Get the jwks_uri from the metadata
    jwks_url = metadata.get("jwks_uri")
    if not jwks_url:
        raise ValueError("No 'jwks_uri' found in the metadata.")
    # Fetch the JWKS content
    jwks_response = requests.get(jwks_url, timeout=10)
    jwks_response.raise_for_status()
    jwks_content = jwks_response.json()

    # Cache the JWKS content
    DISCOVERY_CACHE_REGION.set(cache_key, jwks_content)
    return jwks_content


def validate_token(
        token: str,
        issuer_url: str,
        audience: str,
        token_type: Literal["id_token", "access_token"],
        nonce: Optional[str] = None,
        scopes: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Validate an ID token or access token.

    :param token: The token to validate (ID token or access token).
    :param issuer_url: The issuer URL for the token.
    :param audience: The expected audience (client ID or resource server).
    :param nonce: The nonce from the original request (for ID token validation).
    :param token_type: The type of token ("id_token" or "access_token").
    :param scopes: scopes of access token to validate against EXTRA_OIDC_ACCESS_TOKEN_SCOPE.

    :return: The decoded token if valid.
    """
    jwks_content = get_jwks_content(issuer_url=issuer_url)
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid", None)
    alg = headers.get("alg")
    if not alg:
        raise ValueError("Token header is missing the 'alg' (algorithm) claim.")
    if not kid:
        # in this case use the alg to get the key
        keys = jwks_content.get("keys", [])
        if not keys:
            raise ValueError("No keys found in JWKS.")
        for _key in keys:
            if _key["alg"] == alg:
                key = _key
    else:
        # Find the key in the JWKS matching the 'kid'
        key = next((jwk for jwk in jwks_content.get("keys", []) if jwk.get("kid") == kid), None)
        if not key:
            raise ValueError(f"No matching key found in JWKS for kid: {kid}")

    try:
        public_key = RSAAlgorithm.from_jwk(json.dumps(key))
        if not isinstance(public_key, RSAPublicKey):
            raise ValueError("The provided JWK is not a valid RSAPublicKey.")
    except Exception as e:
        raise ValueError(f"Failed to convert JWK to PEM-format public key: {e}") from e

    # Decode and validate the token
    try:
        decoded_token = jwt.decode(
            token,
            key=public_key,
            audience=audience,
            issuer=issuer_url,
            leeway=LEEWAY_SECS,
            algorithms=[alg],
            options={"verify_signature": True}
        )
    except Exception as e:
        raise CannotAuthenticate(f"Invalid {token_type}: {e}")

    # Additional validation for ID tokens
    if token_type == "id_token" and nonce:
        # openid in scope means sub has to be present in id_token
        if "sub" not in decoded_token:
            raise CannotAuthenticate("Failed to get sub from ID token. 'openid' scope is needed for oidc client")
        if "profile" in ID_TOKEN_EXTRA_SCOPES:
            # according to https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
            profile_claims = ["profile", "name", "given_name", "family_name"]
            has_profile_scope = any(claim in decoded_token for claim in profile_claims)
            if not has_profile_scope:
                raise CannotAuthenticate("Failed to get claims for profile scope from ID token")
        if "email" in ID_TOKEN_EXTRA_SCOPES:
            if "email" not in decoded_token:
                raise CannotAuthenticate("failed to get email from ID token")
        # security for replay attack
        if decoded_token.get("nonce") != nonce:
            raise CannotAuthenticate("Invalid nonce in ID token.")
        if ID_TOKEN_EXTRA_CLAIMS:
            for claim in ID_TOKEN_EXTRA_CLAIMS:
                if claim not in decoded_token:
                    raise CannotAuthenticate(f"Failed to get {claim} from ID token.")

    if token_type == "access_token" and EXTRA_OIDC_ACCESS_TOKEN_SCOPE:
        if not scopes:
            # check the access token scope
            # if no scope in token claim or not supplied then
            # do token introspection, but this is outside the logic of this fuuntion.
            if 'scope' in decoded_token:
                scopes = decoded_token['scope'].split()
        if scopes:
            if not set(EXTRA_OIDC_ACCESS_TOKEN_SCOPE).issubset(scopes):
                raise CannotAuthenticate("Access token doesn't have scope required scope")

    return decoded_token


def request_token(
    audience: str,
    scope: str,
    vo: str = 'def',
    use_cache: bool = True,
) -> Optional[str]:
    """
    Request a token from the provider.

    Return ``None`` if the configuration was not loaded properly or the request
    was unsuccessful.

    :param audience: Audience for the token.
    :param scope: Scope of the token.
    :param vo: Virtual Organization (default: 'def').
    :param use_cache: Whether to use caching for tokens (default: True).
    :return: The access token or None if the request fails.
    """

    idpsecret_config_loader = IDPSecretLoad()
    # TODO: make the request storage token with choice of issuer_nickname if any
    client_config = idpsecret_config_loader.get_vo_clients_config(client_type="client_credential_client", vo=vo)
    if client_config is None:
        return None


    # Access IDP configurations within the VO
    issuer = client_config.get("issuer")
    issuer_token_endpoint = get_discovery_metadata(issuer_url=issuer)["token_endpoint"]  # type: ignore
    client_id = client_config.get("client_id")
    client_secret = client_config.get("client_secret")

    # Create a cache key based on parameters
    cache_key_base = f"scope={scope};vo={vo};audience={audience}"

    key = hashlib.md5(f'{cache_key_base}'.encode()).hexdigest()

    if use_cache and (token := _token_cache_get(key)):
        return token

    # Prepare token request payload
    data = {
        'grant_type': 'client_credentials',
        'scope': scope,
        'audience': audience
    }

    # Request the token
    try:
        response = requests.post(
            url=issuer_token_endpoint,
            auth=(client_id, client_secret),  # type: ignore
            data=data,
            timeout=10
        )
        response.raise_for_status()
        payload = response.json()
        token = payload['access_token']
    except Exception:
        logging.debug('Failed to procure a token', exc_info=True)
        return None

    # Cache the token if caching is enabled
    if use_cache:
        REGION.set(key, token)
    return token


@transactional_session
def get_auth_oidc(
    account: str,
    vo: str = 'def',
    *,
    session: "Session",
    **kwargs
) -> Optional[str]:
    """
    Assemble the authorization request of the Rucio Client tailored to the Rucio user & Identity Provider.

    :param account: Rucio Account identifier.
    :param vo: Virtual Organization (default: 'def').
    :param session: The database session in use.
    :returns: Authorization URL as a string or a redirection URL.
    :raises: CannotAuthenticate if the account does not exist.
    """
    if not account_exists(account, session=session):
        logging.debug("Account %s does not exist.", account)
        return None
    auth_scope_requested = kwargs.get('auth_scope', None)
    auth_scopes_default = DEFAULT_ID_TOKEN_SCOPES + ID_TOKEN_EXTRA_SCOPES + EXTRA_OIDC_ACCESS_TOKEN_SCOPE
    if not auth_scope_requested:
        auth_scope = " ".join(auth_scopes_default)
    else:
        _auth_scopes_requested = auth_scope_requested.split()
        if not set(auth_scopes_default).issubset(set(_auth_scopes_requested)):
            _auth_scopes_requested.extend(scope for scope in auth_scopes_default if scope not in _auth_scopes_requested)
        if not set(EXTRA_OIDC_ACCESS_TOKEN_SCOPE).issubset(set(_auth_scopes_requested)):
            _auth_scopes_requested += EXTRA_OIDC_ACCESS_TOKEN_SCOPE
        auth_scope = " ".join(_auth_scopes_requested)

    audience = EXPECTED_OIDC_AUDIENCE
    issuer_nickname = kwargs.get('issuer', None)

    idpsecret_config_loader = IDPSecretLoad()
    idp_config_vo = idpsecret_config_loader.get_vo_clients_config(client_type="user_auth_client", vo=vo, issuer_nickname=issuer_nickname)
    redirect_url = idp_config_vo["redirect_uris"]
    client_id = idp_config_vo["client_id"]
    issuer = idp_config_vo["issuer"]
    authorization_endpoint = get_discovery_metadata(issuer_url=issuer)["authorization_endpoint"]  # type: ignore

    polling = kwargs.get('polling', False)
    refresh_lifetime = kwargs.get('refresh_lifetime', REFRESH_LIFETIME_H)
    ip = kwargs.get('ip', None)

    try:
        # uuid4 string in order to keep track of responses to outstanding requests (state)
        # and to associate a client session with an ID Token and to mitigate replay attacks (nonce).
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        auth_server = urlparse(authorization_endpoint)

        # Build the query parameters
        query_params = {
            "client_id": client_id,
            "response_type": "code",
            "state": state,
            "nonce": nonce,
            "redirect_uri": redirect_url,
            "scope": auth_scope,
        }
        if config_get_bool('oidc', 'supports_audience', raise_exception=False, default=True):
            query_params['audience'] = audience

        auth_url = f"{auth_server.geturl()}?{urlencode(query_params)}"
        # redirect code is put in access_msg and returned to the user
        access_msg = str(uuid.uuid4())
        if polling:
            access_msg += '_polling'
        # Making sure refresh_lifetime is an integer or None.
        if refresh_lifetime:
            refresh_lifetime = int(refresh_lifetime)
        # Specifying temporarily 5 min lifetime for the authentication session.
        expired_at = datetime.utcnow() + timedelta(seconds=300)
        # saving session parameters into the Rucio DB
        oauth_session_params = models.OAuthRequest(account=account,
                                                   state=state,
                                                   nonce=nonce,
                                                   access_msg=access_msg,
                                                   redirect_msg=auth_url,
                                                   expired_at=expired_at,
                                                   refresh_lifetime=refresh_lifetime,
                                                   ip=ip)
        oauth_session_params.save(session=session)
        _delete_oauth_request_by_account_and_expiration(account, session=session)

        auth_server = urlparse(redirect_url)
        auth_url = build_url('https://' + auth_server.netloc, path='{}auth/oidc_redirect'.format(
            auth_server.path.split('auth/')[0].lstrip('/')), params=access_msg)

        return auth_url

    except Exception as error:
        raise CannotAuthenticate(traceback.format_exc()) from error


@transactional_session
def get_token_oidc(
    auth_query_string: str,
    ip: Optional[str] = None,
    *,
    session: "Session"
) -> Optional[dict[str, Optional[Union[str, bool]]]]:
    """
    Retrieve user's info and tokens from IdP after redirection.

    :param auth_query_string: IdP redirection URL query string.
    :param ip: IP address of the client.
    :param session: The database session in use.
    :returns: Dictionary with token information.
    :raises: CannotAuthenticate if the user session is invalid.
    """
    stopwatch = Stopwatch()
    # parse auth_query_string
    parsed_authquery = parse_qs(auth_query_string)
    try:
        state = parsed_authquery["state"][0]
        code = parsed_authquery["code"][0]
    except KeyError:
        error_msg = f"Authorization failed. Missing 'state' or 'code' in the query string: {auth_query_string}"
        raise CannotAuthorize(error_msg)
    # getting oauth request params from the oauth_requests DB Table
    query = select(
        models.OAuthRequest
    ).where(
        models.OAuthRequest.state == state
    )
    oauth_req_params = session.execute(query).scalar()
    if oauth_req_params is None:
        raise CannotAuthenticate("User related Rucio OIDC session could not keep "
                                 + "track of responses from outstanding requests.")
    req_url = urlparse(oauth_req_params.redirect_msg or '')
    issuer_extracted = req_url.scheme + "://" + req_url.netloc
    query_params = parse_qs(req_url.query)
    clientid_extracted = query_params.get("client_id", [""])[0]
    idpsecret_config_loader = IDPSecretLoad()
    id_config = idpsecret_config_loader.get_config_from_clientid_issuer(client_id=clientid_extracted, issuer=issuer_extracted)
    nonce = oauth_req_params.nonce
    account = oauth_req_params.account
    # get info from config
    issuer_url = id_config["issuer"]
    issuer_token_endpoint = get_discovery_metadata(issuer_url=issuer_url)["token_endpoint"]
    redirect_url = id_config["redirect_uris"]
    client_id = id_config["client_id"]
    client_secret = id_config["client_secret"]

    req_params = parse_qs(req_url.query)
    client_params = {}
    for key in list(req_params):
        client_params[key] = val_to_space_sep_str(req_params[key])
    METRICS.counter(name='IdP_authentication.code_granted').inc()
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_url,
        'client_id': client_id,
        'client_secret': client_secret,
    }

    try:
        response = requests.post(issuer_token_endpoint, data=data, timeout=10)
        response.raise_for_status()
        tokens = response.json()
    except requests.exceptions.RequestException as re:
        raise CannotAuthorize(f"Failed to exchange code for token: {str(re)}")
    except ValueError as ve:
        raise CannotAuthorize(f"Code exchange Decoding JSON failed: {str(ve)}")
    except Exception as e:
        raise CannotAuthorize(f"Unexpected error occured: {str(e)}")

    if "access_token" not in tokens or "id_token" not in tokens:
        raise CannotAuthenticate("ID token or access token missing in the response.")

    # Decode the ID token and validate the nonce
    token_type = "id_token"
    id_token_decoded = validate_token(token=tokens['id_token'], issuer_url=issuer_url, nonce=nonce, audience=client_id, token_type=token_type)
    # Extract the issuer from the ID token
    issuer_from_id_token = id_token_decoded.get("iss")
    sub_from_id_token = id_token_decoded.get("sub")
    identity = oidc_identity_string(sub=sub_from_id_token, iss=issuer_from_id_token)  # type: ignore
    # check if given account has the identity registered
    if not exist_identity_account(identity, IdentityType.OIDC, account, session=session):
        raise CannotAuthenticate("OIDC identity '%s' of the '%s' account is unknown to Rucio." % (identity, account))
    # extract scope, audience, lifetime from access token
    token_type = "access_token"
    scopes = tokens["scope"].split()
    audience_to_validate = EXPECTED_OIDC_AUDIENCE
    _ = validate_token(token=tokens['access_token'], issuer_url=issuer_url, audience=audience_to_validate, token_type=token_type, scopes=scopes)
    scopes = tokens['scope']
    lifetime = datetime.utcnow() + timedelta(seconds=tokens['expires_in'])

    # assemble OIDC table value
    jwt_row_dict = {
        'authz_scope': scopes,
        'audience': audience_to_validate,
        'lifetime': lifetime,
        'account': account,
        'identity': identity
    }
    extra_dict: dict[str, Any] = {'state': state}
    if ip:
        extra_dict['ip'] = ip
    METRICS.counter(name='success').inc()
    if 'refresh_token' in tokens:
        extra_dict['refresh_token'] = tokens['refresh_token']
        extra_dict['refresh'] = True
        extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
        extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)
        METRICS.counter(name='IdP_authorization.refresh_token.saved').inc()
    new_token = __save_validated_token(tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
    METRICS.counter(name='IdP_authorization.access_token.saved').inc()
    __delete_expired_tokens_account(account=account, session=session)
    if oauth_req_params.access_msg:
        if 'http' not in oauth_req_params.access_msg:
            if '_polling' not in oauth_req_params.access_msg:
                fetchcode = str(uuid.uuid4())
                query = update(
                    models.OAuthRequest
                ).where(
                    models.OAuthRequest.state == state
                ).values({
                    models.OAuthRequest.access_msg: fetchcode,
                    models.OAuthRequest.redirect_msg: new_token['token']
                })
                # If Rucio Client was requested to poll the Rucio Auth server
                # for a token automatically, we save the token under a access_msg.
            else:
                query = update(
                    models.OAuthRequest
                ).where(
                    models.OAuthRequest.state == state
                ).values({
                    models.OAuthRequest.access_msg: oauth_req_params.access_msg,
                    models.OAuthRequest.redirect_msg: new_token['token']
                })
            session.execute(query)
            session.commit()
            METRICS.timer('IdP_authorization').observe(stopwatch.elapsed)
            if '_polling' in oauth_req_params.access_msg:
                return {'polling': True}
            elif 'http' in oauth_req_params.access_msg:
                return {'webhome': oauth_req_params.access_msg, 'token': new_token}
            else:
                return {'fetchcode': fetchcode}
    METRICS.timer('IdP_authorization').observe(stopwatch.elapsed)
    return {'token': new_token}


@transactional_session
def refresh_cli_auth_token(
    token_string: str,
    account: str,
    issuer_nickname: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[tuple[str, int]]:
    """
    Refresh CLI authentication token if there is an active refresh token.

    :param token_string: Token string.
    :param account: Rucio account for which token refresh should be considered.
    :param issuer_nickname: Optional issuer nickname.
    :param vo: Virtual Organization (default: 'def').
    :param session: The database session in use.
    :returns: Tuple of (access token, expiration epoch) or None.
    """
    # only validated tokens are in the DB, check presence of token_string
    query = select(
        models.Token
    ).where(
        models.Token.token == token_string,
        models.Token.account == account,
        models.Token.expired_at > datetime.utcnow()
    ).with_for_update(
        skip_locked=True
    )
    account_token = session.execute(query).scalar()

    # if token does not exist in the DB, return None
    if account_token is None:
        logging.debug("No valid token exists for account %s.", account)
        return None

    # protection (!) no further action should be made
    # for token_string without refresh_token in the DB !
    if account_token.refresh_token is None:
        logging.debug("No refresh token exists for account %s.", account)
        return None

    # if the token exists, check if it was refreshed already, if not, refresh it
    if account_token.refresh:
        # protection (!) returning the same token if the token_string
        # is a result of a refresh which happened in the last 5 min
        datetime_min_ago = datetime.utcnow() - timedelta(seconds=300)
        if account_token.updated_at > datetime_min_ago:
            epoch_exp = int(floor((account_token.expired_at - datetime(1970, 1, 1)).total_seconds()))
            new_token_string = account_token.token
            return new_token_string, epoch_exp

        # asking for a refresh of this token
        new_token = __refresh_token_oidc(account_token, issuer_nickname, vo=vo, session=session)
        new_token_string = new_token['token']
        epoch_exp = int(floor((new_token['expires_at'] - datetime(1970, 1, 1)).total_seconds()))
        return new_token_string, epoch_exp

    else:
        # find account token with the same scope,
        # audience and has a valid refresh token
        query = select(
            models.Token
        ).where(
            models.Token.refresh == true(),
            models.Token.refresh_expired_at > datetime.utcnow(),
            models.Token.account == account,
            models.Token.expired_at > datetime.utcnow()
        ).with_for_update(
            skip_locked=True
        )
        new_token = session.execute(query).scalar()
        if new_token is None:
            return None

        # if the new_token has same audience and scopes as the original
        # account_token --> return this token and exp timestamp to the user
        if not new_token.oidc_scope or not account_token.oidc_scope:
            logging.debug("No token could be returned for refresh operation for account %s.", account)
            return None
        if not new_token.audience or not account_token.audience:
            logging.debug("No token could be returned for refresh operation for account %s.", account)
            return None

        new_scope_set = set(new_token.oidc_scope.split())
        account_scope_set = set(account_token.oidc_scope.split())
        new_audience_set = set(new_token.audience.split())
        account_audience_set = set(account_token.audience.split())

        if new_scope_set == account_scope_set and new_audience_set == account_audience_set:
            epoch_exp = int(floor((new_token.expired_at - datetime(1970, 1, 1)).total_seconds()))
            new_token_string = new_token.token
            return new_token_string, epoch_exp
        # if scopes and audience are not the same, return None
        logging.debug("No token could be returned for refresh operation for account %s.", account)
        return None


@METRICS.time_it
@transactional_session
def __refresh_token_oidc(
    token_object: models.Token,
    issuer_nickname: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[dict[str, Any]]:
    """
    Request new access and refresh tokens from the Identity Provider.

    :param token_object: Rucio models.Token DB row object.
    :param issuer_nickname: Optional issuer nickname.
    :param vo: Virtual Organization (default: 'def').
    :param session: The database session in use.
    :returns: A dict with token and expires_at entries if successful, None otherwise.
    :raises: CannotAuthorize if the token refresh fails.
    """
    jwt_row_dict, extra_dict = {}, {}
    jwt_row_dict['account'] = token_object.account
    jwt_row_dict['identity'] = token_object.identity
    extra_dict['refresh_start'] = datetime.utcnow()
    # check if refresh token started in the past already
    if hasattr(token_object, 'refresh_start'):
        if token_object.refresh_start:
            extra_dict['refresh_start'] = token_object.refresh_start
    # check if refresh lifetime is set for the token
    extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
    if token_object.refresh_lifetime:
        extra_dict['refresh_lifetime'] = token_object.refresh_lifetime
    # if the token has been refreshed for time exceeding
    # the refresh_lifetime, the attempt will be aborted and refresh stopped
    if datetime.utcnow() - extra_dict['refresh_start'] > timedelta(hours=extra_dict['refresh_lifetime']):
        __change_refresh_state(token_object.token, refresh=False, session=session)
        return None

    if token_object.refresh_token:
        refresh_token = token_object.refresh_token
        _token = token_object.token
        _decoded_token = jwt.decode(_token, options={"verify_signature": False})
        decoded_refresh_token = jwt.decode(refresh_token, options={"verify_signature": False})
    else:
        raise CannotAuthorize("No refresh token found")
    issuer_url = _decoded_token.get('iss')
    idpsecret_config_loader = IDPSecretLoad()
    idp_config_vo = idpsecret_config_loader.get_vo_clients_config(client_type="user_auth_client", vo=vo, issuer_nickname=issuer_nickname)
    issuer_token_endpoint = get_discovery_metadata(issuer_url=issuer_url)["token_endpoint"]
    client_id = idp_config_vo["client_id"]
    client_secret = idp_config_vo["client_secret"]
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret
    }

    # Send the token refresh request
    try:
        response = requests.post(issuer_token_endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        oidc_tokens = response.json()
    except requests.exceptions.RequestException as re:
        raise CannotAuthorize(f"Failed to refresh token: {str(re)}")
    except ValueError as ve:
        raise CannotAuthorize(f"Refresh token request Decoding JSON failed: {str(ve)}")
    except Exception as e:
        raise CannotAuthorize(f"Unexpected error occured: {str(e)}")

    # Handle the response
    if 'error' in oidc_tokens:
        raise CannotAuthorize(oidc_tokens['error'])
    # save new access and refresh tokens in the DB
    if 'refresh_token' in oidc_tokens and 'access_token' in oidc_tokens:
        audience_to_validate = EXPECTED_OIDC_AUDIENCE
        token_type = "access_token"
        validate_token(token=oidc_tokens['access_token'], issuer_url=issuer_url, audience=audience_to_validate, token_type=token_type, scopes=EXTRA_OIDC_ACCESS_TOKEN_SCOPE)
        # aborting refresh of the original token
        # (keeping it in place until it expires)
        __change_refresh_state(token_object.token, refresh=False, session=session)

        # get access token expiry timestamp
        jwt_row_dict['lifetime'] = datetime.utcnow() + timedelta(seconds=oidc_tokens['expires_in'])
        extra_dict['refresh'] = True
        extra_dict['refresh_token'] = oidc_tokens['refresh_token']
        try:
            values = decoded_refresh_token['exp']
            extra_dict['refresh_expired_at'] = datetime.utcfromtimestamp(float(values['exp']))
        except Exception:
            # 4 day expiry period by default
            extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)
        new_token = __save_validated_token(oidc_tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
        METRICS.counter(name='IdP_authorization.access_token.saved').inc()
        METRICS.counter(name='IdP_authorization.refresh_token.saved').inc()
    else:
        raise CannotAuthorize(f"OIDC identity {token_object.identity} of the {token_object.account} account is did not succeed requesting a new access and refresh tokens.")  # NOQA: W503
    return new_token


@transactional_session
def __change_refresh_state(
    token: str,
    refresh: bool = False,
    *,
    session: "Session"
) -> None:
    """
    Change token refresh state to True/False.

    :param token: The access token for which the refresh value should be changed.
    :param refresh: Boolean indicating the refresh state.
    :param session: The database session in use.
    """
    try:
        query = update(
            models.Token
        ).where(
            models.Token.token == token
        )
        if refresh:
            # update refresh column for a token to True
            query = query.values({
                models.Token.refresh: True
            })
        else:
            query = query.values({
                models.Token.refresh: False,
                models.Token.refresh_expired_at: datetime.utcnow()
            })
        session.execute(query)
    except Exception as error:
        raise RucioException(error.args) from error


@transactional_session
def _delete_oauth_request_by_account_and_expiration(
    account: str,
    *,
    session: "Session"
) -> None:
    """
    Delete an OAuth request by its account and expiration time.

    :param account: The account associated with the OAuth request.
    :param session: Database session in use.
    """
    query = select(
        models.OAuthRequest.state
    ).where(
        models.OAuthRequest.expired_at <= datetime.utcnow(),
        models.OAuthRequest.account == account
    ).with_for_update(
        skip_locked=True
    )

    # Execute the query and fetch all matching states
    oauth_requests = session.execute(query).scalars().all()

    # Process deletion in chunks
    for chunk in chunks(oauth_requests, 100):
        delete_query = delete(
            models.OAuthRequest
        ).where(
            models.OAuthRequest.state.in_(chunk)
        )
        session.execute(delete_query)

    # Commit the transaction
    session.commit()


@transactional_session
def __delete_expired_tokens_account(
    account: "InternalAccount",
    *,
    session: "Session"
) -> None:
    """
    Delete expired tokens from the database.

    :param account: Account to delete expired tokens.
    :param session: The database session in use.
    """
    query = select(
        models.Token.token
    ).where(
        models.Token.expired_at <= datetime.utcnow(),
        models.Token.account == account,
        or_(
            models.Token.refresh_expired_at == null(),
            models.Token.refresh_expired_at <= datetime.utcnow()
        )).with_for_update(
        skip_locked=True
    )
    tokens = session.execute(query).scalars().all()

    for chunk in chunks(tokens, 100):
        delete_query = delete(
            models.Token
        ).prefix_with(
            "/*+ INDEX(TOKENS_ACCOUNT_EXPIRED_AT_IDX) */"
        ).where(
            models.Token.token.in_(chunk)
        )
        session.execute(delete_query)


@transactional_session
def __save_validated_token(token, valid_dict, extra_dict=None, *, session: "Session"):
    """
    Save JWT token to the Rucio DB.

    :param token: Authentication token as a variable-length string.
    :param valid_dict: Validation Rucio dictionary as the output
                       of the __get_rucio_jwt_dict function
    :raises RucioException: on any error
    :returns: A dict with token and expires_at entries.
    """
    try:
        if not extra_dict:
            extra_dict = {}
        new_token = models.Token(account=valid_dict.get('account', None),
                                 token=token,
                                 oidc_scope=valid_dict.get('authz_scope', None),
                                 expired_at=valid_dict.get('lifetime', None),
                                 audience=valid_dict.get('audience', None),
                                 identity=valid_dict.get('identity', None),
                                 refresh=extra_dict.get('refresh', False),
                                 refresh_token=extra_dict.get('refresh_token', None),
                                 refresh_expired_at=extra_dict.get('refresh_expired_at', None),
                                 refresh_lifetime=extra_dict.get('refresh_lifetime', None),
                                 refresh_start=extra_dict.get('refresh_start', None),
                                 ip=extra_dict.get('ip', None))
        new_token.save(session=session)

        return token_dictionary(new_token)

    except Exception as error:
        raise RucioException(error.args) from error


def validate_jwt(
    token: str,
    issuer_nickname: Optional[str] = None,
    *,
    session: "Session"
) -> "TokenValidationDict":
    """
    Validate a JWT token.

    :param token: JWT token string.
    :param session: The database session in use.
    :returns: Token validation dictionary.
    :raises: CannotAuthenticate if the token is invalid.
    """
    try:
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as error:
        raise CannotAuthenticate(f"Invalid token: {error}") from error

    exp = unverified_claims.get('exp', 3600)
    iat = unverified_claims.get('iat', 0)
    _lifetime = exp - iat
    lifetime = datetime.utcnow() + timedelta(seconds=_lifetime)
    issuer_url = unverified_claims["iss"]
    token_type = "access_token"
    audience_to_validate = EXPECTED_OIDC_AUDIENCE
    access_token_decoded = validate_token(token=token, issuer_url=issuer_url, audience=audience_to_validate, token_type=token_type, scopes=EXTRA_OIDC_ACCESS_TOKEN_SCOPE)
    METRICS.counter(name='JSONWebToken.valid').inc()
    identity_string = oidc_identity_string(access_token_decoded['sub'], access_token_decoded['iss'])
    account = get_default_account(identity_string, IdentityType.OIDC, True, session=session)
    vo = account.vo
    idpsecret_config_loader = IDPSecretLoad()
    is_valid_issuer = idpsecret_config_loader.is_valid_issuer(issuer_url=issuer_url, vo=vo)
    if not is_valid_issuer:
        raise CannotAuthenticate(f"token with issuer {issuer_url} is not from valid issuer")
    token_dict = {}
    token_dict['lifetime'] = lifetime
    token_dict['identity'] = identity_string
    # Fallback if 'scope' is missing
    acquired_scopes = access_token_decoded.get('scope', '')
    required_scopes = set(DEFAULT_ID_TOKEN_SCOPES + ID_TOKEN_EXTRA_SCOPES + EXTRA_OIDC_ACCESS_TOKEN_SCOPE)
    if not required_scopes.issubset(set(acquired_scopes.split())):
        token_info  = perform_token_introspection(token=token, issuer_url=issuer_url, issuer_nickname=issuer_nickname, vo=vo)
        if token_info.get("active", False):
            acquired_scopes = token_info['scope']
    token_dict['authz_scope'] = acquired_scopes
    token_dict["audience"] = access_token_decoded["aud"]
    token_dict["account"] = account
    acquired_scopes = token_dict.get('authz_scope', None)
    if not acquired_scopes:
        raise CannotAuthenticate(traceback.format_exc())
    else:
        if not (required_scopes).issubset(set(acquired_scopes.split())):
            raise CannotAuthenticate(f"Presented token has scope {acquired_scopes} doesn't have required scope {str(required_scopes)}.")
    METRICS.counter(name='JSONWebToken.saved').inc()
    __save_validated_token(token, token_dict, session=session)
    return cast("TokenValidationDict", token_dict)


def perform_token_introspection(
        token: str,
        issuer_url: str,
        issuer_nickname: Optional[str] = None,
        vo: str = 'def',
) -> dict[str, Any]:

    """perform token introspection using introspection_endpoint

    :param token:
    :param issuer_url:
    :param issuer_nickname:
    :param vo:
    :raises CannotAuthorize: _description_
    :raises CannotAuthenticate: _description_
    :raises CannotAuthenticate: _description_
    :return _type_: _description_
    """
    # if not scope in access_token claims, get it from introspection_endpoint
    introspection_endpoint = get_discovery_metadata(issuer_url=issuer_url)["introspection_endpoint"]
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    idpsecret_config_loader = IDPSecretLoad()
    auths = idpsecret_config_loader.get_vo_clients_config(client_type="user_auth_client", vo=vo, issuer_nickname=issuer_nickname)
    data = {"token": token}
    try:
        response = requests.post(
            introspection_endpoint,
            headers=headers,
            auth=(str(auths["client_id"]), str(auths["client_secret"])),
            data=data,
            timeout=10
        )
        response.raise_for_status()
        token_info = response.json()
    except requests.exceptions.RequestException as re:
        raise CannotAuthorize(f"Failed to do token introspection: {str(re)}")
    except ValueError as ve:
        raise CannotAuthenticate(f"Token introspection Decoding JSON failed:: {str(ve)}")
    except Exception as e:
        raise CannotAuthenticate(f"Unexpected error occured: {str(e)}")

    return token_info


def oidc_identity_string(sub: str, iss: str) -> str:
    """
    Transform IdP sub claim and issuer URL into user's identity string.

    :param sub: User's SUB claim from the Identity Provider.
    :param iss: Issuer (IdP) URL.
    :returns: OIDC identity string.
    """
    return f"SUB={sub}, ISS={iss}"


def token_dictionary(token: models.Token) -> dict[str, Any]:
    """
    Convert a token model to a dictionary.

    :param token: Token model.
    :returns: Dictionary with token and expires_at entries.
    """
    return {'token': token.token, 'expires_at': token.expired_at}
