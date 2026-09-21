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

from configparser import NoOptionError, NoSectionError
from typing import TYPE_CHECKING, Any, Generic, Optional, TypeVar, cast

from rucio.common.config import config_get
from rucio.common.constants import DEFAULT_VO, POLICY_ALGORITHM_TYPES_LITERAL
from rucio.common.plugins import PolicyPackageAlgorithms

if TYPE_CHECKING:
    from collections.abc import Callable

TokenAlgorithmFn = TypeVar('TokenAlgorithmFn', bound='Callable[..., Any]')


class TokenPolicyAlgorithm(PolicyPackageAlgorithms, Generic[TokenAlgorithmFn]):

    _algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL
    _config_section = 'oidc'

    def __init__(self) -> None:
        super().__init__()

    @classmethod
    def get_configured_algorithm(cls, vo: Optional[str] = None) -> TokenAlgorithmFn:
        if not cls._loaded_policy_modules:
            cls()

        vo = vo or DEFAULT_VO
        try:
            configured_algorithm = str(config_get(cls._config_section, cls._algorithm_type, default='default'))
        except (NoOptionError, NoSectionError, RuntimeError):
            configured_algorithm = 'default'

        result = None
        if configured_algorithm == 'default':
            result = super()._get_default_algorithm(cls._algorithm_type, vo)
        if result is None:
            result = super()._get_one_algorithm(cls._algorithm_type, configured_algorithm)
        return cast(TokenAlgorithmFn, result)

    @classmethod
    def register(cls, name: str, fn: TokenAlgorithmFn) -> None:
        super()._register(cls._algorithm_type, {name: fn})

    @classmethod
    def _module_init(cls) -> None:
        cls.register('default', getattr(cls, 'default'))
