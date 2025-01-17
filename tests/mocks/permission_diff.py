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

# mock permission module that implements only some checks

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing import Optional

    from sqlalchemy.orm import Session

    from rucio.core.common.types import InternalAccount


def has_permission(issuer: "InternalAccount", action: str, kwargs: dict[str, Any], *, session: "Optional[Session]" = None) -> bool:
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer: Account identifier which issues the command..
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    perm = {'add_account': perm_add_account}
    return perm.get(action)(issuer=issuer, kwargs=kwargs, session=session)

def perm_add_account(issuer: "InternalAccount", kwargs: dict[str, Any], *, session: "Optional[Session]" = None) -> bool:
    return False
