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

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO
from rucio.core import policy as policy_core
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission


def list_policy_algorithms(issuer: str, vo: str = DEFAULT_VO) -> dict[str, dict[str, Any]]:
    """
    List the policy package algorithms available for a VO.

    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: A dict with every algorithm type as key and a dict with the names of its registered
              algorithms and the name of its default algorithm as value.
    """
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_policy_algorithms', kwargs={'issuer': issuer}, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot list the policy package algorithms. %s' % (issuer, auth_result.message))

    return policy_core.list_policy_algorithms(vo=vo)
