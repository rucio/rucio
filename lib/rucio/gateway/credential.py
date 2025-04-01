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

from typing import TYPE_CHECKING

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO
from rucio.core import credential
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from rucio.common.constants import RSE_BASE_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL, SUPPORTED_SIGN_URL_SERVICES_LITERAL


def get_signed_url(
    account: str,
    rse: str,
    service: 'SUPPORTED_SIGN_URL_SERVICES_LITERAL',
    operation: 'RSE_BASE_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL',
    url: str,
    lifetime: int,
    vo: str = DEFAULT_VO,
) -> str:
    """
    Get a signed URL for a particular service and operation.

    The signed URL will be valid for 1 hour.

    :param account: Account identifier as a string.
    :param rse: The name of the RSE to which the URL points.
    :param service: The service to authorise, currently only 'gsc'.
    :param operation: The operation to sign, either 'read', 'write', or 'delete'.
    :param url: The URL to sign.
    :param lifetime: Lifetime in seconds.
    :param vo: The vo to act on.

    :returns: Signed URL as a variable-length string.
    """

    kwargs = {'account': account}

    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=account, vo=vo, action='get_signed_url', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not get signed URL for rse=%s, service=%s, operation=%s, url=%s, lifetime=%s. %s' %
                                         (account, rse, service, operation, url, lifetime, auth_result.message))

        # look up RSE ID for name
        rse_id = get_rse_id(rse, vo=vo, session=session)

    return credential.get_signed_url(rse_id, service, operation, url, lifetime)
