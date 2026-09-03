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

from collections.abc import Callable

from rucio.common.constants import POLICY_ALGORITHM_TYPES_LITERAL
from rucio.common.exception import InvalidRequest
from rucio.core.rse import determine_scope_for_rse
from rucio.core.token.algorithm import TokenPolicyAlgorithm
from rucio.core.token.context import StorageTokenContext, StorageTokenOperation


class TokenScope(TokenPolicyAlgorithm[Callable[[StorageTokenContext], str]]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL = 'token_scope'

    @staticmethod
    def default(ctx: StorageTokenContext) -> str:
        if ctx.operation == StorageTokenOperation.FTS_AUTH:
            return 'fts'
        if ctx.operation == StorageTokenOperation.TRANSFER_SOURCE:
            if ctx.rse_id is None:
                raise InvalidRequest(f'rse_id is required for operation {ctx.operation}')
            extra_scopes = ['offline_access'] if ctx.offline_access else []
            return determine_scope_for_rse(
                rse_id=ctx.rse_id,
                scopes=['storage.read'],
                extra_scopes=extra_scopes,
            )
        if ctx.operation == StorageTokenOperation.TRANSFER_DESTINATION:
            if ctx.rse_id is None:
                raise InvalidRequest(f'rse_id is required for operation {ctx.operation}')
            extra_scopes = ['offline_access'] if ctx.offline_access else []
            return determine_scope_for_rse(
                rse_id=ctx.rse_id,
                scopes=['storage.modify', 'storage.read'],
                extra_scopes=extra_scopes,
            )
        raise InvalidRequest(f'Unsupported storage token operation: {ctx.operation}')


TokenScope._module_init()
