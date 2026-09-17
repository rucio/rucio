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
from collections.abc import Callable

from rucio.common.constants import POLICY_ALGORITHM_TYPES_LITERAL
from rucio.core.token.algorithm import TokenPolicyAlgorithm
from rucio.core.token.context import StorageTokenContext, StorageTokenOperation


def token_cache_key(audience: str, scope: str, ctx: StorageTokenContext) -> str:
    parts = [
        f'audience={audience}',
        f'scope={scope}'
    ]
    _ = ctx
    return hashlib.md5(';'.join(parts).encode()).hexdigest()


_CACHEABLE_OPERATIONS = frozenset({
    StorageTokenOperation.FTS_AUTH,
    StorageTokenOperation.TPC_SOURCE,
    StorageTokenOperation.TPC_DESTINATION,
    StorageTokenOperation.TPC_STAGE,
    StorageTokenOperation.TPC_POLL,
    StorageTokenOperation.CENTRAL_DELETE,
})


class TokenCache(TokenPolicyAlgorithm[Callable[[StorageTokenContext], bool]]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL = 'token_cache'

    @staticmethod
    def default(ctx: StorageTokenContext) -> bool:
        return ctx.operation in _CACHEABLE_OPERATIONS


TokenCache._module_init()
