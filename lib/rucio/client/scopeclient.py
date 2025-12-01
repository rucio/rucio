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

    """Scope client class for working with Rucio scopes.

    In Rucio, a *scope* is the namespace that groups datasets, files and
    containers underneath an account. Scopes provide isolation and ownership
    boundaries—clients prepend the scope to data identifiers (DIDs) to avoid
    collisions and to enforce the account responsible for the data. Common
    examples include ``user.<username>`` or project-level scopes such as
    ``dataops``.
    """

    SCOPE_BASEURL = 'accounts'

    def add_scope(
            self,
            account: str,
            scope: str
    ) -> bool:
        """
        Create a new scope for an account.

        Scopes represent the namespaces that own datasets and files. Once
        created, the scope can be used in DIDs (e.g. ``<scope>:<dataset>``) to
        make ownership and visibility explicit.

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
            If the scope already exists for the account.
        AccountNotFound
            If the provided account does not exist.

        Examples
        --------
        ??? Example

            Create a scope for the ``dataops`` account. If the scope already
            exists for the account, a ``Duplicate`` exception is raised.

            ```python
            from rucio.client.scopeclient import ScopeClient

            # The client will pick up authentication from the standard Rucio
            # configuration (e.g. ~/.ruciorc or RUCIO_* environment variables).
            client = ScopeClient()

            client.add_scope(account="dataops", scope="user.test")
            ```
        """

        path = '/'.join(
            [self.SCOPE_BASEURL, account, 'scopes', quote_plus(scope)]
        )
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.POST)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(
                headers=r.headers,
                status_code=r.status_code,
                data=r.content
            )
            raise exc_cls(exc_msg)

    def list_scopes(self) -> list[str]:
        """
        List all scopes belonging to the client's authenticated account.

        Returns
        -------
        list[str]
            Names of all scopes configured in Rucio.

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
            exc_cls, exc_msg = self._get_exception(
                headers=r.headers,
                status_code=r.status_code,
                data=r.content
            )
            raise exc_cls(exc_msg)

    def list_scopes_for_account(self, account: str) -> list[str]:
        """
        List all scopes assigned to an account.

        Scopes define the namespaces an account controls. This call surfaces
        every namespace available to the account so callers can construct DIDs
        or present account-level permissions.

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
            exc_cls, exc_msg = self._get_exception(
                headers=r.headers,
                status_code=r.status_code,
                data=r.content
            )
            raise exc_cls(exc_msg)
