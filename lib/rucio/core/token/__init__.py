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

from typing import Optional

from rucio.common.constants import DEFAULT_VO
from rucio.core.token.audience import TokenAudience
from rucio.core.token.context import StorageTokenContext, StorageTokenOperation
from rucio.core.token.request import TokenRequest
from rucio.core.token.scope import TokenScope

__all__ = [
    'StorageTokenContext',
    'StorageTokenOperation',
    'TokenAudience',
    'TokenRequest',
    'TokenScope',
    'get_token_for_operation',
]


def _vo_from_ctx(ctx: StorageTokenContext) -> str:
    if ctx.vo:
        return ctx.vo
    if ctx.account is not None:
        vo = getattr(ctx.account, 'vo', None)
        if vo:
            return vo
    return DEFAULT_VO


def get_token_for_operation(ctx: StorageTokenContext) -> Optional[str]:
    vo = _vo_from_ctx(ctx)
    audience = TokenAudience.get_configured_algorithm(vo)(ctx)
    scope = TokenScope.get_configured_algorithm(vo)(ctx)
    return TokenRequest.get_configured_algorithm(vo)(audience, scope, ctx)
