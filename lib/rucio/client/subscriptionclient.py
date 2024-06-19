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
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterator


class SubscriptionClient(BaseClient):

    """SubscriptionClient class for working with subscriptions"""

    SUB_BASEURL = 'subscriptions'

    def add_subscription(
            self,
            name: str,
            account: str,
            filter_: dict[str, Any],
            replication_rules: dict[str, Any],
            comments: str,
            lifetime: Union[int, Literal[False]],
            retroactive: bool,
            dry_run: bool,
            priority: int = 3
    ) -> str:
        """
        Adds a new subscription which will be verified against every new added file and dataset

        :param name: Name of the subscription
        :param account: Account identifier
        :param filter_: Dictionary of attributes by which the input data should be filtered
                       **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
        :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
        :param comments: Comments for the subscription
        :param lifetime: Subscription's lifetime (days); False if subscription has no lifetime
        :param retroactive: Flag to know if the subscription should be applied on previous data
        :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
        :param priority: The priority of the subscription (3 by default)
        """
        path = self.SUB_BASEURL + '/' + account + '/' + name
        url = build_url(choice(self.list_hosts), path=path)
        if retroactive:
            raise NotImplementedError('Retroactive mode is not implemented')
        if filter_ and not isinstance(filter_, dict):
            raise TypeError('filter should be a dict')
        if replication_rules and not isinstance(replication_rules, list):
            raise TypeError('replication_rules should be a list')
        data = dumps({'options': {'filter': filter_, 'replication_rules': replication_rules, 'comments': comments,
                                  'lifetime': lifetime, 'retroactive': retroactive, 'dry_run': dry_run, 'priority': priority}})
        result = self._send_request(url, type_='POST', data=data)
        if result.status_code == codes.created:   # pylint: disable=no-member
            return result.text
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
            raise exc_cls(exc_msg)

    def list_subscriptions(
            self,
            name: Optional[str] = None,
            account: Optional[dict[str, Any]] = None
    ) -> Union["Iterator[dict[str, Any]]", list]:
        """
        Returns a dictionary with the subscription information :
        Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

        :param name: Name of the subscription
        :param account: Account identifier
        :returns: Dictionary containing subscription parameter
        :raises: exception.NotFound if subscription is not found
        """
        path = self.SUB_BASEURL
        if account:
            path += '/%s' % (account)
            if name:
                path += '/%s' % (name)
        elif name:
            path += '/Name/%s' % (name)
        else:
            path += '/'
        url = build_url(choice(self.list_hosts), path=path)
        result = self._send_request(url, type_='GET')
        if result.status_code == codes.ok:   # pylint: disable=no-member
            return self._load_json_data(result)
        if result.status_code == codes.not_found:
            return []
        exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
        raise exc_cls(exc_msg)

    def update_subscription(
            self,
            name,
            account: Optional[str] = None,
            filter_: Optional[dict[str, Any]] = None,
            replication_rules: Optional[dict[str, Any]] = None,
            comments: Optional[str] = None,
            lifetime: Optional[Union[int, Literal[False]]] = None,
            retroactive: Optional[bool] = None,
            dry_run: Optional[bool] = None,
            priority: Optional[int] = None
    ) -> Literal[True]:
        """
        Updates a subscription

        :param name: Name of the subscription
        :param account: Account identifier
        :param filter_: Dictionary of attributes by which the input data should be filtered
                       **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
        :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
        :param comments: Comments for the subscription
        :param lifetime: Subscription's lifetime (days); False if subscription has no lifetime
        :param retroactive: Flag to know if the subscription should be applied on previous data
        :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
        :param priority: The priority of the subscription
        :raises: exception.NotFound if subscription is not found
        """
        if not account:
            account = self.account
        if retroactive:
            raise NotImplementedError('Retroactive mode is not implemented')
        path = self.SUB_BASEURL + '/' + account + '/' + name  # type: ignore
        url = build_url(choice(self.list_hosts), path=path)
        if filter_ and not isinstance(filter_, dict):
            raise TypeError('filter should be a dict')
        if replication_rules and not isinstance(replication_rules, list):
            raise TypeError('replication_rules should be a list')
        data = dumps({'options': {'filter': filter_, 'replication_rules': replication_rules, 'comments': comments,
                                  'lifetime': lifetime, 'retroactive': retroactive, 'dry_run': dry_run, 'priority': priority}})
        result = self._send_request(url, type_='PUT', data=data)
        if result.status_code == codes.created:   # pylint: disable=no-member
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
            raise exc_cls(exc_msg)

    def list_subscription_rules(
            self,
            account: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List the associated rules of a subscription.

        :param account: Account of the subscription.
        :param name:    Name of the subscription.
        """

        path = '/'.join([self.SUB_BASEURL, account, name, 'Rules'])
        url = build_url(choice(self.list_hosts), path=path)
        result = self._send_request(url, type_='GET')
        if result.status_code == codes.ok:   # pylint: disable=no-member
            return self._load_json_data(result)
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
            raise exc_cls(exc_msg)
