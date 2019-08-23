# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Diego Ciangottini <diego.ciangottini@gmail.com>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class RequestClient(BaseClient):

    REQUEST_BASEURL = 'requests'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None,
                 auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(RequestClient, self).__init__(rucio_host, auth_host, account, ca_cert,
                                            auth_type, creds, timeout, user_agent, vo=vo)

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

        path = '/'.join(['requests', quote_plus(scope), quote_plus(name), rse])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')

        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
