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
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url


class ScopeClient(BaseClient):

    """
    Scope client class for working with Rucio scopes.

    In Rucio, a scope partitions the DID namespace within a VO. A DID is
    defined by the pair (scope, name), represented as ``<scope>:<name>``; this
    partitioning avoids name collisions and supports ownership boundaries
    across accounts. Scope naming is typically deployment-specific
    (examples include ``user.jdoe``, ``data22_13p6TeV``, and ``demo``).
    """

    SCOPE_BASEURL = 'accounts'

    def add_scope(
            self,
            account: str,
            scope: str
    ) -> bool:
        """
        Create a new scope for an account.

        After creation, the account can register DIDs in this scope.

        Parameters
        ----------
        account
            Name of the account that will own the scope.
        scope
            Name of the scope to create.

        Returns
        -------
        bool
            Literal ``True`` when the scope is created successfully.

        Raises
        ------
        Duplicate
            If the scope already exists.
        AccountNotFound
            If the provided account does not exist.

        Examples
        --------
        ??? Example

            Create a scope for the ``dataops`` account. If the scope already
            exists, a ``Duplicate`` exception is raised.

            ```python
            from rucio.client.scopeclient import ScopeClient

            # The client reads authentication settings from rucio.cfg (or from the file
            # pointed to by RUCIO_CONFIG) and from related RUCIO_* environment variables.
            client = ScopeClient()

            client.add_scope(account="dataops", scope="user.test")
            ```
        """

        path = '/'.join([self.SCOPE_BASEURL, account, 'scopes', quote_plus(scope)])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.POST)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_scopes(self) -> list[str]:
        """
        List all scopes in the current VO.

        Returns
        -------
        list[str]
            Names of all scopes in the current VO.

        Raises
        ------
        RucioException
            Raised when the request is not successful.
        """

        path = '/'.join(['scopes/'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            scopes = loads(r.text)
            return scopes
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_scopes_for_account(self, account: str) -> list[str]:
        """
        List all scopes assigned to an account.

        Use this method to inspect which scopes are assigned to an account (useful for
        discovery and pre-checks such as before the creation of DIDs for that account).

        Parameters
        ----------
        account
            The Rucio account to list scopes for.

        Returns
        -------
        list[str]
            Names of the scopes that belong to the account.

        Raises
        ------
        AccountNotFound
            If the account does not exist.
        ScopeNotFound
            If no scopes are defined for the account.

        Examples
        --------
        ??? Example

            List all scopes assigned to the account "dataops".

            ```python
            from rucio.client.scopeclient import ScopeClient
            client = ScopeClient()
            scopes = client.list_scopes_for_account(account="dataops")
            for scope in scopes:
                print(scope)
            ```
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
