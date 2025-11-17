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
from typing import TYPE_CHECKING
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Any, Literal, Union


class ScopeClient(BaseClient):

    """Scope client class for working with rucio scopes"""

    SCOPE_BASEURL = 'accounts'

    def add_scope(
            self,
            account: str,
            scope: str
    ) -> bool:
        """
        Sends the request to add a new scope.

        Parameters
        ----------
        account :
            The name of the account to add the scope to.
        scope :
            The name of the new scope.

        Returns
        -------
            True if scope was created successfully.

        Raises
        ------
        Duplicate
            If scope already exists.
        AccountNotFound
            If account doesn't exist.
        """

        path = '/'.join([self.SCOPE_BASEURL, account, 'scopes', quote_plus(scope)])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.POST)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_scopes(self) -> 'Union[list[str], Iterable[dict[Literal["scope", "account"], Any]]]':
        """
        Sends the request to list all scopes.

        Returns
        -------
        A list containing the scopes and their owner (if server >= 40.0) or the list of scopes
        """

        path = '/'.join(["scopes", "owner"])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            scopes = loads(r.text)
            return scopes
        elif r.status_code == codes.not_found:
            # Backwards compatibility - see issue #8125
            path = "scopes/"
            url = build_url(choice(self.list_hosts), path=path)
            r = self._send_request(url, method=HTTPMethod.GET)
            if r.status_code == codes.ok:
                scopes = loads(r.text)
                return scopes
            else:
                exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
                raise exc_cls(exc_msg)

        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_scopes_for_account(self, account: str) -> list[str]:
        """
        Sends the request to list all scopes for a rucio account.

        Parameters
        ----------
        account :
            The rucio account to list scopes for.

        Returns
        -------
            A list containing the names of all scopes for a rucio account.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.
        ScopeNotFound
            If no scopes exist for account.
        """

        path = '/'.join([self.SCOPE_BASEURL, account, 'scopes/'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            scopes = loads(r.text)
            return scopes
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_scope(self, account: str, scope: str) -> bool:
        """
        Change the ownership of a scope

        Parameters
        ----------
        account :
            New account to assign as scope owner
        scope :
            Scope to change ownership of

        Returns
        -------
        bool
            True if the operation was successful

        Raises
        ------
        AccountNotFound
            If account doesn't exist.
        ScopeNotFound
            If scope doesn't exist.
        CannotAuthenticate, AccessDenied
            Insufficient permission/incorrect credentials to change ownership.
        """

        path = '/'.join(['scopes', account, scope])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.PUT)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
