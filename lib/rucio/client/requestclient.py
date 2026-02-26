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
from rucio.common.constants import HTTPMethod, TransferLimitDirection
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


class RequestClient(BaseClient):

    REQUEST_BASEURL = 'requests'

    def list_requests(
            self,
            src_rse: str,
            dst_rse: str,
            request_states: 'Sequence[str]'
    ) -> 'Iterator[dict[str, Any]]':
        """Return latest request details

        Returns
        -------
        request information
        """
        path = '/'.join([self.REQUEST_BASEURL, 'list']) + '?' + '&'.join(['src_rse={}'.format(src_rse), 'dst_rse={}'.format(
            dst_rse), 'request_states={}'.format(request_states)])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_requests_history(
            self,
            src_rse: str,
            dst_rse: str,
            request_states: 'Sequence[str]',
            offset: int = 0,
            limit: int = 100
    ) -> 'Iterator[dict[str, Any]]':
        """Return historical request details

        Returns
        -------
        request information
        """
        path = '/'.join([self.REQUEST_BASEURL, 'history', 'list']) + '?' + '&'.join(['src_rse={}'.format(src_rse), 'dst_rse={}'.format(
            dst_rse), 'request_states={}'.format(request_states), 'offset={}'.format(offset), 'limit={}'.format(limit)])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_request_by_did(
            self,
            name: str,
            rse: str,
            scope: Optional[str] = None
    ) -> 'Iterator[dict[str, Any]]':
        """Return latest request details for a DID
        Parameters
        ----------
        name:
            DID
        rse:
            Destination RSE name
        scope:
            rucio scope, defaults to None

        Raises
        -------
        exc_cls: from BaseClient._get_exception

        Returns
        -------
        request information
        """

        if scope is not None:
            path = '/'.join([self.REQUEST_BASEURL, quote_plus(scope), quote_plus(name), rse])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_request_history_by_did(
            self,
            name: str,
            rse: str,
            scope: Optional[str] = None
    ) -> 'Iterator[dict[str, Any]]':
        """
        Return latest request details for a DID

        Parameters
        ----------
        name:
            DID
        rse:
            Destination RSE name
        scope:
            rucio scope, defaults to None

        Raises
        -------
        exc_cls: from BaseClient._get_exception

        Returns
        -------
        request information
        """

        if scope is not None:
            path = '/'.join([self.REQUEST_BASEURL, 'history', quote_plus(scope), quote_plus(name), rse])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_transfer_limits(
            self
    ) -> 'Iterator[dict[str, Any]]':
        """Returns all the transfer limits

        :returns: transfer limits

        Note:
        -----
        Added in version 38.0.0
        """
        path = '/'.join([self.REQUEST_BASEURL, 'transfer_limits'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_transfer_limit(
            self,
            rse_expression: str,
            activity: Optional[str] = None,
            direction: TransferLimitDirection = TransferLimitDirection.DESTINATION,
            max_transfers: Optional[int] = None,
            volume: Optional[int] = None,
            deadline: Optional[int] = None,
            strategy: Optional[str] = None,
            transfers: Optional[int] = None,
            waitings: Optional[int] = None,
    ) -> Literal[True]:
        """Set the transfer limit for a given RSE

        :param rse_expression: RSE expression string.
        :param activity: The activity.
        :param direction: The direction in which this limit applies (source/destination)
        :param max_transfers: Maximum transfers.
        :param volume: Maximum transfer volume in bytes.
        :param deadline: Maximum waiting time in hours until a datasets gets released.
        :param strategy: defines how to handle datasets: `fifo` (each file released separately) or `grouped_fifo` (wait for the entire dataset to fit)
        :param transfers: Current number of active transfers
        :param waitings: Current number of waiting transfers

        :returns: True if the transfer limit was deleted

        Note:
        -----
        Added in version 38.0.0
        """
        path = '/'.join([self.REQUEST_BASEURL, 'transfer_limits'])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'rse_expression': rse_expression, 'activity': activity,
                      'direction': direction.value, 'max_transfers': max_transfers,
                      'volume': volume, 'deadline': deadline, 'strategy': strategy,
                      'transfers': transfers, 'waitings': waitings})
        r = self._send_request(url, method=HTTPMethod.PUT, data=data)

        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_transfer_limit(
            self,
            rse_expression: str,
            activity: Optional[str] = None,
            direction: TransferLimitDirection = TransferLimitDirection.DESTINATION
    ) -> Literal[True]:
        """Delete the transfer limit for a given RSE

        :param rse_expression: RSE expression string.
        :param activity: The activity.
        :param direction: The direction in which this limit applies (source/destination)

        :returns: True if the transfer limit was deleted

        Note:
        -----
        Added in version 38.0.0
        """
        path = '/'.join([self.REQUEST_BASEURL, 'transfer_limits'])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'rse_expression': rse_expression, 'activity': activity, 'direction': direction.value})
        r = self._send_request(url, method=HTTPMethod.DELETE, data=data)

        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
