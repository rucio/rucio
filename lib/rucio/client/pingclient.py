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
from rucio.common.utils import build_url


class PingClient(BaseClient):

    """Ping client class"""

    def ping(self):
        """
        Sends a ping request to the rucio server.

        :return: Dictonnary with server information
        """

        headers = None
        path = 'ping'
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers=headers, type_='GET')

        if r.status_code == codes.ok:
            server_info = loads(r.text)
            return server_info

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
