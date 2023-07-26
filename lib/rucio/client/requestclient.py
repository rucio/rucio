# -*- coding: utf-8 -*-
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

from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class RequestClient(BaseClient):

    REQUEST_BASEURL = 'requests'

    def list_requests(self, src_rse, dst_rse, request_states):
        """Return latest request details

        :return: request information
        :rtype: dict
        """
        path = '/'.join([self.REQUEST_BASEURL, 'list']) + '?' + '&'.join(['src_rse={}'.format(src_rse), 'dst_rse={}'.format(
            dst_rse), 'request_states={}'.format(request_states)])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_requests_history(self, src_rse, dst_rse, request_states, offset=0, limit=100):
        """Return historical request details

        :return: request information
        :rtype: dict
        """
        path = '/'.join([self.REQUEST_BASEURL, 'history', 'list']) + '?' + '&'.join(['src_rse={}'.format(src_rse), 'dst_rse={}'.format(
            dst_rse), 'request_states={}'.format(request_states), 'offset={}'.format(offset), 'limit={}'.format(limit)])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_request_by_did(self, name, rse, scope=None):
        """Return latest request details for a DID

        :param name: DID
        :type name: str
        :param rse: Destination RSE name
        :type rse: str
        :param scope: rucio scope, defaults to None
        :param scope: str, optional
        :raises exc_cls: from BaseClient._get_exception
        :return: request information
        :rtype: dict
        """

        path = '/'.join([self.REQUEST_BASEURL, quote_plus(scope), quote_plus(name), rse])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_request_history_by_did(self, name, rse, scope=None):
        """Return latest request details for a DID

        :param name: DID
        :type name: str
        :param rse: Destination RSE name
        :type rse: str
        :param scope: rucio scope, defaults to None
        :param scope: str, optional
        :raises exc_cls: from BaseClient._get_exception
        :return: request information
        :rtype: dict
        """

        path = '/'.join([self.REQUEST_BASEURL, 'history', quote_plus(scope), quote_plus(name), rse])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
