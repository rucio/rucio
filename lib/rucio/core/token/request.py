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
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional, Union

import requests
from dogpile.cache.api import NoValue
from jwkest.jwt import JWT

from rucio.common.cache import MemcacheRegion
from rucio.common.constants import POLICY_ALGORITHM_TYPES_LITERAL
from rucio.core import oidc as oidc_core
from rucio.core.monitor import MetricManager
from rucio.core.token.algorithm import TokenPolicyAlgorithm
from rucio.core.token.cache import TokenCache
from rucio.core.token.context import StorageTokenContext, vo_from_ctx

_NON_FORM_EXTRA_KEYS = frozenset({'fts_hostname', 'expiry_time'})
_RESERVED_FORM_KEYS = frozenset({'grant_type', 'audience', 'scope', 'expires_in'})

REGION = MemcacheRegion(expiration_time=oidc_core.TOKEN_MAX_LIFETIME)
METRICS = MetricManager(module=__name__)


def _expires_in_seconds(expiry_time: Union[datetime, int]) -> int:
    if isinstance(expiry_time, datetime):
        aware = expiry_time if expiry_time.tzinfo is not None else expiry_time.replace(tzinfo=timezone.utc)
        return max(0, int((aware - datetime.now(tz=timezone.utc)).total_seconds()))
    return int(expiry_time)


@METRICS.time_it
def _token_cache_get(
    key: str,
    min_lifetime: int = oidc_core.TOKEN_MIN_LIFETIME,
) -> Optional[str]:
    value = REGION.get(key)
    if isinstance(value, NoValue):
        METRICS.counter('token_cache.miss').inc()
        return None

    if isinstance(value, str):
        try:
            payload = JWT().unpack(value).payload()
        except Exception:
            METRICS.counter('token_cache.invalid').inc()
            return None
    else:
        METRICS.counter('token_cache.invalid').inc()
        return None

    now = datetime.now(tz=timezone.utc).timestamp()
    expiration = payload.get('exp', 0)    # type: ignore
    if now + min_lifetime > expiration:
        METRICS.counter('token_cache.expired').inc()
        return None

    METRICS.counter('token_cache.hit').inc()
    return value


def _token_cache_set(key: str, value: str) -> None:
    """Store a token in the cache."""
    REGION.set(key, value)


class TokenRequest(TokenPolicyAlgorithm[Callable[[str, str, StorageTokenContext], Optional[str]]]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL = 'token_request'

    @staticmethod
    def default(audience: str, scope: str, ctx: StorageTokenContext) -> Optional[str]:

        if not all([oidc_core.OIDC_CLIENT_ID, oidc_core.OIDC_CLIENT_SECRET, oidc_core.OIDC_PROVIDER_ENDPOINT]):
            if oidc_core.OIDC_CONFIGURATION_RUN or not oidc_core.__load_oidc_configuration():
                return None

        use_cache = TokenCache.get_configured_algorithm(vo_from_ctx(ctx))(ctx)
        key = hashlib.md5(f'audience={audience};scope={scope}'.encode()).hexdigest()
        if use_cache and (token := _token_cache_get(key)):
            return token

        form: dict[str, Any] = {
            'grant_type': 'client_credentials',
            'audience': audience,
            'scope': scope,
        }

        if ctx.extras.get('expiry_time') is not None:
            form['expires_in'] = _expires_in_seconds(ctx.extras['expiry_time'])

        for extra_key, value in ctx.extras.items():
            if extra_key in _NON_FORM_EXTRA_KEYS or extra_key in _RESERVED_FORM_KEYS or value is None:
                continue
            form[extra_key] = value

        try:
            response = requests.post(
                url=oidc_core.OIDC_PROVIDER_ENDPOINT,
                auth=(oidc_core.OIDC_CLIENT_ID, oidc_core.OIDC_CLIENT_SECRET),
                data=form,
            )
            response.raise_for_status()
            payload = response.json()
            token = payload['access_token']
        except Exception:
            logging.debug('Failed to procure a token', exc_info=True)
            return None

        if use_cache:
            _token_cache_set(key, token)

        return token


TokenRequest._module_init()
