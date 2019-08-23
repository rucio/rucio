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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json


class ImportClient(BaseClient):
    """RSE client class for importing data into Rucio"""

    IMPORT_BASEURL = 'import'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None,
                 auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(ImportClient, self).__init__(rucio_host, auth_host, account, ca_cert,
                                           auth_type, creds, timeout, user_agent, vo=vo)

    def import_data(self, data):
        """
        Imports data into Rucio.

        :param data: a dict containing data to be imported into Rucio.
        """
        path = '/'.join([self.IMPORT_BASEURL])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return r.text
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
