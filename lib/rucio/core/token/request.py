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
from datetime import datetime, timezone
from typing import Any, Optional, Union

import requests

from rucio.common.constants import POLICY_ALGORITHM_TYPES_LITERAL
from rucio.core import oidc as oidc_core
from rucio.core.token.algorithm import TokenPolicyAlgorithm
from rucio.core.token.context import StorageTokenContext

_NON_FORM_EXTRA_KEYS = frozenset({'fts_hostname'})
_RESERVED_FORM_KEYS = frozenset({'grant_type', 'audience', 'scope'})


def _expires_in_seconds(expiry_time: Union[datetime, int]) -> int:
    if isinstance(expiry_time, datetime):
        aware = expiry_time if expiry_time.tzinfo is not None else expiry_time.replace(tzinfo=timezone.utc)
        return max(0, int((aware - datetime.now(tz=timezone.utc)).total_seconds()))
    return int(expiry_time)


class TokenRequest(TokenPolicyAlgorithm[Callable[[str, str, StorageTokenContext], Optional[str]]]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL = 'token_request'

    @staticmethod
    def default(audience: str, scope: str, ctx: StorageTokenContext) -> Optional[str]:

        if not all([oidc_core.OIDC_CLIENT_ID, oidc_core.OIDC_CLIENT_SECRET, oidc_core.OIDC_PROVIDER_ENDPOINT]):
            if oidc_core.OIDC_CONFIGURATION_RUN or not oidc_core.__load_oidc_configuration():
                return None

        form: dict[str, Any] = {
            'grant_type': 'client_credentials',
            'audience': audience,
            'scope': scope,
        }
        
        if ctx.expiry_time is not None:
            form['expires_in'] = _expires_in_seconds(ctx.expiry_time)

        for key, value in ctx.extras.items():
            if key in _NON_FORM_EXTRA_KEYS or key in _RESERVED_FORM_KEYS or value is None:
                continue
            # 'expires_in' is handled here
            form[key] = value

        try:
            # 
            response = requests.post(
                url=oidc_core.OIDC_PROVIDER_ENDPOINT,
                auth=(oidc_core.OIDC_CLIENT_ID, oidc_core.OIDC_CLIENT_SECRET),
                data=form,
            )
            response.raise_for_status()
            payload = response.json()
            return payload['access_token']
        except Exception:
            logging.debug('Failed to procure a token', exc_info=True)
            return None


TokenRequest._module_init()
