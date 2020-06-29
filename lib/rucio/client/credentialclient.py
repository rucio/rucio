# Copyright 2019 CERN for the benefit of the ATLAS collaboration.
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
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class CredentialClient(BaseClient):
    """Credential client class for working with URL signing"""

    CREDENTIAL_BASEURL = 'credentials'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None,
                 auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(CredentialClient, self).__init__(rucio_host, auth_host, account, ca_cert,
                                               auth_type, creds, timeout, user_agent, vo=vo)

    def get_signed_url(self, rse, service, operation, url, lifetime=3600):
        """
        Return a signed version of the given URL for the given operation.

        :param rse: The name of the RSE the URL points to.
        :param service: The service the URL points to (gcs, s3, swift)
        :param operation: The desired operation (read, write, delete)
        :param url: The URL to sign
        :param lifetime: The desired lifetime of the URL in seconds

        :return: The signed URL string
        """
        path = '/'.join([self.CREDENTIAL_BASEURL, 'signurl'])
        params = {}
        params['lifetime'] = lifetime
        params['rse'] = rse
        params['svc'] = service
        params['op'] = operation
        params['url'] = url
        rurl = build_url(choice(self.list_hosts), path=path, params=params)
        r = self._send_request(rurl, type='GET')

        if r.status_code == codes.ok:
            return r.text

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
