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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Optional

from jwkest.jwt import JWT

from rucio.common.constants import DEFAULT_VO, POLICY_ALGORITHM_TYPES_LITERAL
from rucio.core.token.algorithm import TokenPolicyAlgorithm
from rucio.core.token.context import StorageTokenContext, StorageTokenOperation

def _jwt_payload(token: str) -> Optional[dict[str, Any]]:
    try:
        payload = JWT().unpack(token).payload()
    except Exception:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _scope_values(payload: dict[str, Any]) -> list[str]:
    scope = payload.get('scope', '')
    if isinstance(scope, list):
        return [str(item) for item in scope]
    return str(scope).split()


class TokenManaged(TokenPolicyAlgorithm[Callable[[StorageTokenContext, str], bool]]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL = 'token_managed'

    @staticmethod
    def default(ctx: StorageTokenContext, token: str) -> bool:
        payload = _jwt_payload(token)
        if payload is None:
            return False
        return 'offline_access' in _scope_values(payload)


TokenManaged._module_init()


@dataclass(frozen=True)
class JobTransferToken:
    token: str
    operation: StorageTokenOperation = StorageTokenOperation.TPC_SOURCE
    rse_type: Optional[str] = None


def unmanaged_tokens_for_job(
        tokens: Sequence[JobTransferToken],
        vo: Optional[str] = None,
        logger: Callable[..., Any] = logging.log,
) -> bool:
    if not tokens:
        return False

    algorithm = TokenManaged.get_configured_algorithm(vo or DEFAULT_VO)
    managed = []
    for item in tokens:
        ctx = StorageTokenContext(operation=item.operation, vo=vo)
        managed.append(algorithm(ctx, item.token))

    if any(managed) != all(managed):
        logger(logging.WARNING, 'Mixed managed and unmanaged storage tokens in one FTS job; submitting as managed')
    return not any(managed)
