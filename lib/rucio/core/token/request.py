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

import logging
from collections.abc import Callable
from configparser import NoOptionError, NoSectionError
from datetime import datetime, timezone
from typing import Optional, Union

import requests
from dogpile.cache.api import NoValue
from jwkest.jwt import JWT

from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get
from rucio.common.constants import POLICY_ALGORITHM_TYPES_LITERAL
from rucio.core import oidc as oidc_core
from rucio.core.token.algorithm import TokenPolicyAlgorithm
from rucio.core.token.cache import TokenCache, token_cache_key
from rucio.core.token.context import StorageTokenContext, vo_from_ctx

REGION = MemcacheRegion(expiration_time=oidc_core.TOKEN_MAX_LIFETIME)

_TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
_ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
_Form = Union[dict[str, str], list[tuple[str, str]]]


def _storage_credentials_ready() -> bool:
    if all([oidc_core.OIDC_CLIENT_ID, oidc_core.OIDC_CLIENT_SECRET, oidc_core.OIDC_PROVIDER_ENDPOINT]):
        return True
    if oidc_core.OIDC_CONFIGURATION_RUN or not oidc_core._load_oidc_configuration():
        return False
    return True


def _post(form: _Form, issued_token_type: Optional[str] = None) -> Optional[str]:
    try:
        response = requests.post(
            url=oidc_core.OIDC_PROVIDER_ENDPOINT,
            auth=(oidc_core.OIDC_CLIENT_ID, oidc_core.OIDC_CLIENT_SECRET),
            data=form,
        )
        response.raise_for_status()
        payload = response.json()
        token = payload['access_token']
    except Exception as error:
        body = getattr(getattr(error, 'response', None), 'text', None)
        logging.debug('Failed to procure a storage token: %s', body, exc_info=True)
        return None

    token_type = payload.get('token_type', 'Bearer')
    if str(token_type).lower() != 'bearer':
        logging.error('IdP issued a %r token; storage needs a Bearer token.', token_type)
        return None
    declared = payload.get('issued_token_type')
    if issued_token_type and declared not in (None, issued_token_type):
        logging.error('IdP issued token type %r; requested %r.', declared, issued_token_type)
        return None
    return token


def _configured_idp_name() -> str:
    try:
        name = config_get('oidc', 'idp', default='iam')
    except (NoOptionError, NoSectionError, RuntimeError):
        name = 'iam'
    return str(name).strip().lower() or 'iam'


def _request_iam(audience: str, scope: str) -> Optional[str]:
    return _post({
        'grant_type': 'client_credentials',
        'audience': audience,
        'scope': scope,
    })


def _request_rfc(audience: str, scope: str) -> Optional[str]:
    subject = _post({
        'grant_type': 'client_credentials',
        'scope': scope,
    })
    if subject is None:
        return None

    audiences = [item for item in audience.split() if item]
    if not audiences:
        return subject

    form: list[tuple[str, str]] = [
        ('grant_type', _TOKEN_EXCHANGE_GRANT),
        ('subject_token', subject),
        ('subject_token_type', _ACCESS_TOKEN_TYPE),
        ('requested_token_type', _ACCESS_TOKEN_TYPE),
        ('scope', scope),
    ]
    form.extend(('audience', item) for item in audiences)
    return _post(form, issued_token_type=_ACCESS_TOKEN_TYPE)


def _request_token(audience: str, scope: str) -> Optional[str]:
    name = _configured_idp_name()
    if name in ('iam', 'cilogon'):
        return _request_iam(audience, scope)
    if name == 'rfc':
        return _request_rfc(audience, scope)
    logging.error('Unknown [oidc] idp %r. Expected iam, cilogon, or rfc.', name)
    return None


def _token_cache_get(
    key: str,
    min_lifetime: int = oidc_core.TOKEN_MIN_LIFETIME,
) -> Optional[str]:
    value = REGION.get(key)
    if isinstance(value, NoValue):
        return None

    if isinstance(value, str):
        try:
            payload = JWT().unpack(value).payload()
        except Exception:
            return None
    else:
        return None

    now = datetime.now(tz=timezone.utc).timestamp()
    expiration = payload.get('exp', 0)    # type: ignore
    if now + min_lifetime > expiration:
        return None

    return value


def _token_cache_set(key: str, value: str) -> None:
    REGION.set(key, value)


class TokenRequest(TokenPolicyAlgorithm[Callable[[str, str, StorageTokenContext], Optional[str]]]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL = 'token_request'

    @staticmethod
    def default(audience: str, scope: str, ctx: StorageTokenContext) -> Optional[str]:
        if not _storage_credentials_ready():
            return None

        use_cache = TokenCache.get_configured_algorithm(vo_from_ctx(ctx))(ctx)
        key = token_cache_key(audience, scope, ctx)
        if use_cache and (token := _token_cache_get(key)):
            return token

        token = _request_token(audience, scope)
        if use_cache and token:
            _token_cache_set(key, token)
        return token


TokenRequest._module_init()
