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

from typing import Any

from rucio.common import config
from rucio.common.constants import DEFAULT_VO, POLICY_ALGORITHM_TYPES_LITERAL
from rucio.common.plugins import PolicyPackageAlgorithms


def list_policy_algorithms(vo: str = DEFAULT_VO) -> dict[str, dict[str, Any]]:
    """
    List the policy package algorithms available for a VO.

    In multi-VO mode the algorithms are namespaced with the VO prefix at registration, so only the
    algorithms of the requested VO are returned. In single-VO mode everything the installed policy
    package provides is returned.

    :param vo: The VO to list the algorithms and to resolve the default algorithms for.
    :returns: A dict with every algorithm type as key and a dict with the names of its registered
              algorithms and the name of its default algorithm as value.
    """
    registry = PolicyPackageAlgorithms()
    registered: dict[POLICY_ALGORITHM_TYPES_LITERAL, list[str]] = registry.list_algorithms()

    if config.config_get_bool('common', 'multi_vo', default=False):
        registered = {
            algorithm_type: [name for name in names if name.lower().startswith(vo.lower())]
            for algorithm_type, names in registered.items()
        }

    return {
        algorithm_type: {
            'algorithms': names,
            'default': registry.default_algorithm_name(algorithm_type, vo),
        }
        for algorithm_type, names in registered.items()
    }
