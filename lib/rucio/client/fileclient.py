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
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus
from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class FileClient(BaseClient):
    """Dataset client class for working with dataset"""

    BASEURL = 'files'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, user_agent='rucio-clients'):
        """ Constructor """
        super(FileClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def list_file_replicas(self, scope, lfn):
        """
        List file replicas.

        :param scope: the scope.
        :param lfn: the lfn.

        :return: List of replicas.
        """
        path = '/'.join([self.BASEURL, quote_plus(scope), quote_plus(lfn), 'rses'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='GET')

        if r.status_code == codes.ok:
            rses = loads(r.text)
            return rses
        else:
            print(r.status_code)
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
