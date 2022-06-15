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
from rucio.common.utils import build_url


class CredentialClient(BaseClient):
    """Credential client class for working with URL signing"""

    CREDENTIAL_BASEURL = 'credentials'

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
        r = self._send_request(rurl, type_='GET')

        if r.status_code == codes.ok:
            return r.text

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
