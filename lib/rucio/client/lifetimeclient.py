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

from json import loads
from typing import TYPE_CHECKING, Any, Optional

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url, render_json

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from datetime import datetime

    from rucio.db.sqla.constants import LifetimeExceptionsState


class LifetimeClient(BaseClient):

    """Lifetime client class for working with Lifetime Model exceptions"""

    LIFETIME_BASEURL = 'lifetime_exceptions'

    def list_exceptions(
            self,
            exception_id: Optional[str] = None,
            states: Optional['Sequence[LifetimeExceptionsState]'] = None
    ) -> 'Iterator[dict[str, Any]]':
        """
        Lists lifetime model exceptions that allow extending data lifetimes beyond their configured policies.

        The lifetime model exceptions are used to override the default lifecycle policies for data identifiers
        (files, datasets, containers, or archives) that need to be kept longer than usual. These exceptions
        can be filtered by their ID or approval state (this feature is not available yet).

        Parameters
        ----------
        exception_id :
            The unique identifier of a specific exception. If provided, returns only that exception.
        states :
            Filter exceptions by their states. Possible values are:
            * `A` (APPROVED): Exception was approved
            * `R` (REJECTED): Exception was rejected
            * `W` (WAITING): Exception is waiting for approval by an admin (or other authorized account)

        Returns
        -------

            An iterator of dictionaries containing the exception details:
            * `id`: The unique identifier of the exception
            * `scope`: The scope of the data identifier
            * `name`: The name of the data identifier
            * `did_type`: Type of the data identifier:
                `F` (file), `D` (dataset), `C` (container), `A` (archive),
                `X` (deleted file), `Y` (deleted dataset), `Z` (deleted container)
            * `account`: The account that requested the exception
            * `pattern`: Pattern used for matching data identifiers
            * `comments`: User provided comments explaining the exception
            * `state`: Current state of the exception
            * `created_at`: When the exception was created (returned as timestamp string)
            * `expires_at`: When the exception expires (returned as timestamp string)
        """

        path = self.LIFETIME_BASEURL + '/'
        params = {}
        if exception_id:
            params['exception_id'] = exception_id
        if states:
            params['states'] = exception_id
        url = build_url(choice(self.list_hosts), path=path, params=params)

        result = self._send_request(url, method=HTTPMethod.GET)
        if result.status_code == codes.ok:
            lifetime_exceptions = self._load_json_data(result)
            return lifetime_exceptions
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code)
            raise exc_cls(exc_msg)

    def add_exception(
            self,
            dids: list[dict[str, Any]],
            account: str,
            pattern: str,
            comments: str,
            expires_at: 'datetime'
    ) -> dict[str, Any]:
        """
        Creates a lifetime model exception request to extend the expiration date of data identifiers (DIDs).

        These exceptions allow requesting extensions to DIDs' lifetimes, subject to approval and configured
        maximum extension periods. The request includes details about which DIDs should have extended
        lifetimes, who is requesting it, and why it's needed.

        Parameters
        ----------
        dids :
            List of dictionaries containing the data identifiers to be excepted.
            Each dictionary must contain:
            * **scope** : The scope of the data identifier
            * **name** : The name of the data identifier
        account :
            The account requesting the exception
        pattern :
            Associated pattern for the exception request
        comments :
            Justification for why the exception is needed (e.g. "Needed for my XYZ analysis..")
        expires_at :
            When the exception should expire (datetime object)

        Returns
        -------

            A dictionary containing:
            * **exceptions** : Dictionary mapping exception IDs to lists of DIDs that were successfully added
            * **unknown** : List of DIDs that could not be found
            * **not_affected** : List of DIDs that did not qualify for an exception

        """

        path = self.LIFETIME_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        data = {'dids': dids, 'account': account, 'pattern': pattern, 'comments': comments, 'expires_at': expires_at}
        result = self._send_request(url, method=HTTPMethod.POST, data=render_json(**data))
        if result.status_code == codes.created:
            return loads(result.text)
        exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
        raise exc_cls(exc_msg)
