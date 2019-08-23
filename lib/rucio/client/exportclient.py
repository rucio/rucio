# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, parse_response


class ExportClient(BaseClient):
    """RSE client class for exporting data from Rucio"""

    EXPORT_BASEURL = 'export'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None,
                 auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(ExportClient, self).__init__(rucio_host, auth_host, account, ca_cert,
                                           auth_type, creds, timeout, user_agent, vo=vo)

    def export_data(self):
        """
        Export data.

        :returns: A dict containing data
        """
        path = '/'.join([self.EXPORT_BASEURL])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return parse_response(r.text)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
