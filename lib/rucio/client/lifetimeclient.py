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

from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json


class LifetimeClient(BaseClient):

    """Lifetime client class for working with Lifetime Model exceptions"""

    LIFETIME_BASEURL = 'lifetime_exceptions'

    def list_exceptions(self, exception_id=None, states=None):
        """
        List exceptions to Lifetime Model.

        :param id:         The id of the exception
        :param states:     The states to filter
        """

        path = self.LIFETIME_BASEURL + '/'
        params = {}
        if exception_id:
            params['exception_id'] = exception_id
        if states:
            params['states'] = exception_id
        url = build_url(choice(self.list_hosts), path=path, params=params)

        result = self._send_request(url)
        if result.status_code == codes.ok:
            lifetime_exceptions = self._load_json_data(result)
            return lifetime_exceptions
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code)
            raise exc_cls(exc_msg)

    def add_exception(self, dids, account, pattern, comments, expires_at):
        """
        Add exceptions to Lifetime Model.

        :param dids:        The list of dids
        :param account:     The account of the requester.
        :param pattern:     The account.
        :param comments:    The comments associated to the exception.
        :param expires_at:  The expiration date of the exception.

        returns:            The id of the exception.
        """
        path = self.LIFETIME_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        data = {'dids': dids, 'account': account, 'pattern': pattern, 'comments': comments, 'expires_at': expires_at}
        result = self._send_request(url, type_='POST', data=render_json(**data))
        if result.status_code == codes.created:
            return loads(result.text)
        exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
        raise exc_cls(exc_msg)
