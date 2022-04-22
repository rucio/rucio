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

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, parse_response


class ExportClient(BaseClient):
    """RSE client class for exporting data from Rucio"""

    EXPORT_BASEURL = 'export'

    def export_data(self, distance=True):
        """
        Export RSE data (RSE, settings, attributes and distance).
        :param distance: To include the distance.

        :returns: A dict containing data
        """
        payload = {'distance': distance}
        path = '/'.join([self.EXPORT_BASEURL])
        url = build_url(choice(self.list_hosts), path=path, params=payload)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return parse_response(r.text)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
