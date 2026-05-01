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

from json import dumps
from typing import TYPE_CHECKING, Any, Literal, Optional
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterator


class AccountClient(BaseClient):

    """Account client class for working with Rucio accounts"""

    ACCOUNTS_BASEURL = 'accounts'

    def add_account(self, account: str, type_: Literal["USER", "GROUP", "SERVICE"], email: str) -> Literal[True]:
        """
        Create a new account. Accounts can be used to set permissions, identities, and quotas.

        Parameters
        ----------
        account :
            The name of the account.
        type_ :
            The account type.
            Choose from USER (for a single user),
            GROUP (an account shared across multiple users)
            or SERVICE (operator or for automated processes).
        email :
            The email address associated with the account.

        Returns
        -------
            True if account was created.

        Raises
        ------
        Duplicate
            If account already exists.

        Examples
        --------
        ??? Example

            Create a new user account for jdoe.

            ```python
            from rucio.client.client import Client
            client = Client()
            client.add_account('jdoe', 'USER', 'jdoe@cern.ch')
            ```

        See Also
        --------
        rucio.client.accountclient.AccountClient.delete_account
        rucio.client.accountclient.AccountClient.get_account
        rucio.client.accountclient.AccountClient.add_identity
        rucio.client.accountclient.AccountClient.set_account_limit
        """

        data = dumps({'type': type_, 'email': email})
        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, method=HTTPMethod.POST, data=data)
        if res.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def delete_account(self, account: str) -> Literal[True]:
        """
        Disable an account.
        When an account is disabled, the account can no longer be used for authentication, but it will still exist in the system.
        Alternatively, an account can temporary disabled by suspending the account via `update_account(account, 'status', 'suspended')`.

        Parameters
        ----------
        account :
            The name of the account.

        Returns
        -------
            True if account was disabled successfully.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        Examples
        --------
        ??? Example

            Delete the 'jdoe' account.

            ```python
            from rucio.client.client import Client
            client = Client()
            client.delete_account('jdoe')
            ```

        See Also
        --------
        rucio.client.accountclient.AccountClient.add_account
        rucio.client.accountclient.AccountClient.get_account
        rucio.client.accountclient.AccountClient.list_accounts
        rucio.client.accountclient.AccountClient.update_account
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, method=HTTPMethod.DELETE)

        if res.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_account(self, account: str) -> Optional[dict[str, Any]]:
        """
        Send the request to get information about a given account.

        Parameters
        ----------
        account :
            The name of the account.

        Returns
        -------
            A dictionary of settings for an account.
                ** `account`** [str]: The name of the account.
                ** `type`** [str]: The account type (USER, GROUP, or SERVICE).
                ** `email`** [str]: The email address associated with the account.
                ** `status`** [str]: The account status (active, disabled, or suspended).
                ** `created_at`** [datetime.datetime]: When the account was created.
                ** `updated_at`** [datetime.datetime]: When the account was last updated.
                ** `deleted_at`** [datetime.datetime]: When the account was deleted. None if the account is not deleted.
                ** `suspended_at`** [datetime.datetime]: When the account was suspended. None if the account is not suspended.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.add_account
        rucio.client.accountclient.AccountClient.update_account
        rucio.client.accountclient.AccountClient.add_account_attribute
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            acc = self._load_json_data(res)
            return next(acc)
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def update_account(self, account: str, key: Literal["status", "type", "email"], value: Any) -> Literal[True]:
        """
        Update a property of an account.

        Parameters
        ----------
        account :
            Name of the account.
        key :
            Account property. Choose from `status` (active, disabled, or suspended) or `type` (USER, GROUP, or SERVICE), or email.
        value :
            Property value.

        Returns
        -------
            True if successful.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        Examples
        --------
        ??? Example
            Suspend the 'jdoe' account, can be used a 'ban' operation to temporarily disable an account.

            ```python
            from rucio.client.client import Client
            client = Client()
            client.update_account('jdoe', 'status', 'suspended')
            ```

        ??? Example
            Change the email associated with a service account

            ```python
            from rucio.client.client import Client
            client = Client()
            client.update_account('my_service_account', 'email', 'new.services@cern.ch')
            ```
        """
        data = dumps({key: value})
        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, method=HTTPMethod.PUT, data=data)

        if res.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_accounts(
            self,
            account_type: Optional[str] = None,
            identity: Optional[str] = None,
            filters: Optional[dict[str, Any]] = None
    ) -> "Iterator[dict[str, Any]]":
        """
        List all accounts, with the ablity to filter based on type, identity, or other account attributes.

        Parameters
        ----------
        account_type :
            The account type.
        identity :
            The identity key name. For example, x509 DN or a username.
        filters :
            A dictionary of key-value pairs to filter on accounts.
            Can be an acount setting or an account attribute.

        Returns
        -------
            An iterator of dictionaries of settings for accounts.
                ** `account`** [str]: The name of the account.
                ** `type`** [str]: The account type (USER, GROUP, or SERVICE).
                ** `email`** [str]: The email address associated with the account.

            If no accounts match the provided criteria, an empty iterator is returned.

        Examples
        --------
        ??? Example
            List all 'USER' account names.
            ```python
            from rucio.client.client import Client
            client = Client()
            user_accounts = client.list_accounts(account_type='USER')
            for account in user_accounts:
                print(account['account'])
            ```
        ??? Example
            List all service account names with an 'admin' attribute
            ```python
            from rucio.client.client import Client
            client = Client()
            service_accounts = client.list_accounts(account_type='SERVICE', filters={'admin': True})
            for account in service_accounts:
                print(account['account'])

        """
        path = '/'.join([self.ACCOUNTS_BASEURL])
        url = build_url(choice(self.list_hosts), path=path)
        params = {}
        if account_type:
            params['account_type'] = account_type
        if identity:
            params['identity'] = identity
        if filters:
            for key in filters:
                params[key] = filters[key]

        res = self._send_request(url, method=HTTPMethod.GET, params=params)

        if res.status_code == codes.ok:
            accounts = self._load_json_data(res)
            return accounts
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def whoami(self) -> Optional[dict[str, Any]]:
        """
        Get information about account whose token is used.
        Recommended as a debugging tool to check authentication via client.

        Returns
        -------
            Settings for the authenticated account.
                ** `account`** [str]: The name of the account.
                ** `type`** [str]: The account type (USER, GROUP, or SERVICE).
                ** `email`** [str]: The email address associated with the account.
                ** `status`** [str]: The account status (active, disabled, or suspended).
                ** `created_at`** [datetime.datetime]: When the account was created.
                ** `updated_at`** [datetime.datetime]: When the account was last updated.
                ** `deleted_at`** [datetime.datetime]: When the account was deleted. None if the account is not deleted.
                ** `suspended_at`** [datetime.datetime]: When the account was suspended. None if the account is not suspended.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_account
        """

        return self.get_account('whoami')

    def add_identity(
            self,
            account: str,
            identity: str,
            authtype: str,
            email: str,
            default: bool = False,
            password: Optional[str] = None
    ) -> Literal[True]:
        """
        Add a membership association between identity and account.

        Parameters
        ----------
        account :
            The account name.
        identity :
            The identity key name. For example x509 DN, or a username.
        authtype :
            The type of the authentication (x509, gss, userpass).
        email :
            The Email address associated with the identity.
        default :
            If True, the account should be used by default with the provided identity.
        password :
            Password if authtype is userpass.

        Returns
        -------
            True if successful.

        Raises
        ------
        IdentityError
            If you are missing a required element of the identity
        Duplicate
            If the identity is already associated with the account.

        """

        data = dumps({'identity': identity, 'authtype': authtype, 'default': default, 'email': email, 'password': password})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'identities'])

        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, method=HTTPMethod.POST, data=data)

        if res.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def del_identity(
            self,
            account: str,
            identity: str,
            authtype: str
    ) -> Literal[True]:
        """
        Delete an identity's membership association with an account.

        Parameters
        ----------
        account :
            The account name.
        identity :
            The identity key name. For example x509 DN, or a username.
        authtype :
            The type of the authentication (x509, gss, userpass).

        Returns
        -------
            True if successful.

        Raises
        ------
        IdentityError
            Identity does not exist or is not associated with the account.
        """

        data = dumps({'identity': identity, 'authtype': authtype})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'identities'])

        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, method=HTTPMethod.DELETE, data=data)

        if res.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_identities(self, account: str) -> "Iterator[dict[str, Any]]":
        """
        List all identities on an account.

        Parameters
        ----------
        account :
            The account name.

        Returns
        -------
            An iterator of dictionaries of settings for identities associated with the account.
            ** `type` ** [str]: The type of the authentication (x509, gss, userpass).
            ** `identity` ** [str]: The identity key name. For example x509 DN, or a username.
            ** `email` ** [str]: The Email address associated with the identity.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.
        """
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'identities'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            identities = self._load_json_data(res)
            return identities
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_account_rules(self, account: str) -> "Iterator[dict[str, Any]]":
        """
        List the associated rules that an account owns.

        Parameters
        ----------
        account :
            The account name.

        Returns
        -------
            An iterator of dictionaries of settings for rules associated with the account.
            Keys are the attributes of the rule as given by `RuleClient.get_replication_rule`

        See Also
        --------
        rucio.client.ruleclient.RuleClient.get_replication_rule
        rucio.client.accountclient.RuleClient.add_replication_rule
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'rules'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def get_account_limits(self, account: str, rse_expression: str, locality: Literal['local', 'global']) -> dict[str, Any]:
        """
        Return the account limits for the given rse and locality.

        Parameters
        ----------
        account :
            The account name.
        rse_expression :
            Valid RSE expression.
        locality :
            The scope of the account limit. 'local' or 'global'.

        Returns
        -------
            Dictionary with keys of the RSEs and the account limit for each RSE in bytes.
            If the RSE expression resolves to no RSEs, {rse_expression: None} is returned.

        Raises
        ------
        UnsupportedOperation
            If the provided locality is not 'local' or 'global'.
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.clients.accountclient.AccountClient.get_global_account_limit
        rucio.clients.accountclient.AccountClient.get_local_account_limit
        """

        if locality == 'local':
            return self.get_local_account_limit(account, rse_expression)
        elif locality == 'global':
            return self.get_global_account_limit(account, rse_expression)
        else:
            from rucio.common.exception import UnsupportedOperation
            raise UnsupportedOperation('The provided locality (%s) for the account limit was invalid' % locality)

    def set_account_limit(
            self,
            account: str,
            rse: str,
            bytes_: int,
            locality: Literal['local', 'global']
    ) -> Literal[True]:
        """
        Sets an account limit for a given limit scope.
        Limits are defined as a combination of rse{_expression} and locality.
        A "local" limit applied a limit to a specific RSE,
        while a "global" limit applies to all RSEs that match the provided RSE expression.

        Parameters
        ----------
        account :
            The name of the account.
        rse :
            The rse name or expression.
        bytes_ :
            The limit in bytes.
        locality :
            The scope of the account limit.

        Returns
        -------
            True if quota was created successfully.

        Raises
        ------
        UnsupportedOperation
            If the provided locality is not 'local' or 'global'.
        AccountNotFound
            If account doesn't exist.

        Examples
        --------
        ??? Example
            Set a local account limit of 10GB for the 'jdoe' account on the 'MOCK' RSE.

            ```python
            from rucio.client.client import Client
            client = Client()
            client.set_account_limit('jdoe', 'MOCK', 1e10, 'local')
            ```

        ??? Example
            Set a global account limit of 1TB for the 'jdoe' account on all RSEs that match the expression 'MOCK*'.
            If a local limit already exists for an RSE that matches the expression,
            the local limit will override the global limit for that RSE.

            So if the previous example's limit is already place,
            this will result in a 10GB limit for 'jdoe' on 'MOCK' and a 1TB limit for 'jdoe' on all other RSEs that match 'MOCK*'.

            ```python
            from rucio.client.client import Client
            client = Client()
            client.set_account_limit('jdoe', 'MOCK*', 1e12, 'global')
            ```
        See Also
        --------
        rucio.clients.accountclient.AccountClient.set_local_account_limit
        rucio.clients.accountclient.AccountClient.set_global_account_limit
        """

        if locality == 'local':
            return self.set_local_account_limit(account, rse, bytes_)
        elif locality == 'global':
            return self.set_global_account_limit(account, rse, bytes_)
        else:
            from rucio.common.exception import UnsupportedOperation
            raise UnsupportedOperation('The provided scope (%s) for the account limit was invalid' % locality)

    def delete_account_limit(
            self,
            account: str,
            rse: str,
            locality: Literal['local', 'global']
    ) -> Literal[True]:
        """
        Deletes an account limit for a given limit scope.

        Parameters
        ----------
        account :
            The name of the account.
        rse :
            The rse name.
        locality :
            The scope of the account limit.

        Returns
        -------
            True if limit was deleted successfully.

        Raises
        ------
        UnsupportedOperation
            If the provided locality is not 'local' or 'global'.
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.set_account_limit
        """

        if locality == 'local':
            return self.delete_local_account_limit(account, rse)
        elif locality == 'global':
            return self.delete_global_account_limit(account, rse)
        else:
            from rucio.common.exception import UnsupportedOperation
            raise UnsupportedOperation('The provided scope (%s) for the account limit was invalid' % locality)

    def get_global_account_limit(self, account: str, rse_expression: str) -> dict[str, Any]:
        """
        List the account limit for the specific RSE expression.

        Parameters
        ----------
        account :
            The account name.
        rse_expression :
            The rse expression.

        Returns
        -------
            Dictionary with keys of the RSE Expression and the account limit for the RSE Expression in bytes.
            Does not resolve each RSE Expression to RSEs.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_account_limits
        rucio.client.accountclient.AccountClient.get_local_account_limits
        rucio.client.rseclient.RSEClient.list_rses
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'global', quote_plus(rse_expression)])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_global_account_limits(self, account: str) -> dict[str, Any]:
        """
        List all RSE expression limits of this account.

        Parameters
        ----------
        account :
            The account name.

        Raises
        ------
        InvalidRSEExpression
            If the account has a limit with a RSE Expression limits that do not resolve to RSEs
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_account_limits
        rucio.client.accountclient.AccountClient.get_local_account_limits
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'global'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_local_account_limits(self, account: str) -> dict[str, Any]:
        """
        List the all local rse limits of this account.

        Parameters
        ----------
        account :
            The account name.

        Returns
        -------
            Dictionary with keys of the RSEs and the account limit for each RSE in bytes

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_account_limits
        rucio.client.accountclient.AccountClient.get_global_account_limits
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'local'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_local_account_limit(self, account: str, rse: str) -> dict[str, Any]:
        """
        Get the local limit for this account on a specified RSE.
        Equivalent to `get_local_account_limits(account)[rse]`

        Parameters
        ----------
        account :
            The account name.
        rse :
            The rse name.

        Returns
        -------
            Dictionary with keys of the RSE and the account limit for the RSE in bytes.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.
        RSENotFound
            If RSE doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_account_limits
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'local', rse])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def set_local_account_limit(
            self,
            account: str,
            rse: str,
            bytes_: int
    ) -> Literal[True]:
        """
        Sends the request to set an account limit for an account.

        Parameters
        ----------
        account :
            The name of the account.
        rse :
            The rse name.
        bytes_ :
            The limit in bytes.

        Returns
        -------
            True if quota was created successfully.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.
        RSENotFound
            If RSE doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.set_global_account_limit
        rucio.client.accountclient.AccountClient.get_local_account_limit
        rucio.client.accountclient.AccountClient.get_account_limits
        """
        data = dumps({'bytes': bytes_})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, "limits", 'local', rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.POST, data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_local_account_limit(
            self,
            account: str,
            rse: str
    ) -> Literal[True]:
        """
        Remove a local account limit

        Parameters
        ----------
        account :
            The name of the account.
        rse :
            The rse name.

        Returns
        -------
            True if quota was removed successfully.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.
        RSENotFound
            If RSE doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.set_account_limit
        rucio.client.accountclient.AccountClient.set_local_account_limit
        rucio.client.accountclient.AccountClient.get_local_account_limit
        rucio.client.accountclient.AccountClient.delete_account_limit
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, "limits", "local", rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.DELETE)

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_global_account_limit(
            self,
            account: str,
            rse_expression: str,
            bytes_: int
    ) -> Literal[True]:
        """
        Set a global account limit for an account.
        A global limit applies to all RSEs that match the RSE Expression.
        If a local limit exists that matches the expression, the local limit takes precedence.

        Parameters
        ----------
        account :
            The name of the account.
        rse_expression :
            The rse expression.
        bytes_ :
            The limit in bytes.

        Returns
        -------
            True if quota was created successfully.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.set_local_account_limit
        rucio.client.accountclient.AccountClient.get_global_account_limit
        """

        data = dumps({'bytes': bytes_})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, "limits", 'global', quote_plus(rse_expression)])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.POST, data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_global_account_limit(
            self,
            account: str,
            rse_expression: str
    ) -> Literal[True]:
        """
        Remove a global account limit.

        Parameters
        ----------
        account :
            The name of the account.
        rse_expression :
            The rse expression.

        Returns
        -------
            True if quota was removed successfully.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.set_account_limit
        rucio.client.accountclient.AccountClient.set_global_account_limit
        rucio.client.accountclient.AccountClient.get_global_account_limit
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, "limits", 'global', quote_plus(rse_expression)])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.DELETE)

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_local_account_usage(self, account: str, rse: Optional[str] = None) -> "Iterator[dict[str, Any]]":
        """
        List the account usage for one or all rses of this account.

        Parameters
        ----------
        account :
            The account name.
        rse :
            The rse name, used to filter the usage to a specific RSE. If None, all RSEs used by the account are returned.

        Returns
        -------
            An iterator of dictionaries with the keys:
                **`rse` **: RSE Name.
                ** `bytes` **: Number of bytes used on the RSE.
                ** `'files` **: Number of files on the RSE belonging to the account.
                ** `bytes_limit` **: If a limit is set, the usage limit for the account.
                ** `bytes_remaining` **: `bytes_limit` - `bytes_used`.

        Raise
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_global_account_usage
        """
        if rse:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'local', rse])
        else:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'local'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def get_global_account_usage(self, account: str, rse_expression: Optional[str] = None) -> "Iterator[dict[str, Any]]":
        """
        List the account usage for one or all RSE expressions of this account.

        Parameters
        ----------
        account :
            The account name.
        rse_expression :
            The rse expression.

        Returns
        -------
            An iterator of dictionaries with the keys:
                **`rse` **: RSE Name.
                ** `bytes` **: Number of bytes used on the RSE.
                ** `'files` **: Number of files on the RSE belonging to the account.
                ** `bytes_limit` **: If a limit is set, the usage limit for the account.
                ** `bytes_remaining` **: `bytes_limit` - `bytes_used`.

        Raise
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.get_local_account_usage
        """
        if rse_expression:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'global', quote_plus(rse_expression)])
        else:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'global'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def get_account_usage_history(self, account: str, rse: str) -> dict[str, Any]:
        """
        List the account usage history of this account on rse.

        Parameters
        ----------
        account :
            The account name.
        rse :
            The rse name.
        """
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage/history', rse])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_account_attributes(self, account: str) -> "Iterator[dict[dict[str, Any], Any]]":
        """
        List the attributes for an account.
        Attributes are attribute key-value pairs that can be added to accounts.
        They can be used in permission policies or for other custom uses.

        Parameters
        ----------
        account :
            The account name.

        Returns
        -------
            An iterator of list of dictionaries of account attributes, as key-value pairs.

        Examples
        --------
        ??? Example
            List all attributes for the 'jdoe' account.

            ```python
            from rucio.client.client import Client
            client = Client()
            attributes = client.list_account_attributes('jdoe')
            for attribute in attributes: # Each attribute is returned as a list of dictionaries
                print(f"Attribute key: {attribute[0]['key']}, Attribute value: {attribute[0]['value']}")
            ```

        See Also
        --------
        rucio.client.accountclient.AccountClient.add_account_attribute
        rucio.client.accountclient.AccountClient.delete_account_attribute
        """
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'attr/'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.GET)
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def add_account_attribute(self, account: str, key: str, value: Any) -> Literal[True]:
        """
        Add an attribute to an account.

        Parameters
        ----------
        account :
            The account name.
        key :
            The attribute key.
        value :
            The attribute value.

        Returns
        -------
            True if successful.

        Raises
        ------
        AccountNotFound
            If account doesn't exist.

        See Also
        --------
        rucio.client.accountclient.AccountClient.list_account_attributes
        rucio.client.accountclient.AccountClient.delete_account_attribute
        """

        data = dumps({'key': key, 'value': value})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.POST, data=data)
        if res.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def delete_account_attribute(self, account: str, key: str) -> Literal[True]:
        """
        Delete an attribute for an account.

        Parameters
        ----------
        account :
            The account name.
        key :
            The attribute key.

        Returns
        -------
            True if successful.

        Raises
        ------
        AccountNotFound
            If account doesn't exist or does not have the attribute key.

        See Also
        --------
        rucio.client.accountclient.AccountClient.list_account_attributes
        rucio.client.accountclient.AccountClient.add_account_attribute
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, method=HTTPMethod.DELETE, data=None)
        if res.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)
