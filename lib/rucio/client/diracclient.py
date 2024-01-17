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

from json import dumps

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class DiracClient(BaseClient):

    """DataIdentifier client class for working with data identifiers"""

    DIRAC_BASEURL = 'dirac'

    def add_files(self, lfns, ignore_availability=False, parents_metadata=None):
        """
        Bulk add files :
        - Create the file and replica.
        - If doesn't exist create the dataset containing the file as well as a rule on the dataset on ANY sites.
        - Create all the ascendants of the dataset if they do not exist

        :param lfns: List of lfn (dictionary {'lfn': <lfn>, 'rse': <rse>, 'bytes': <bytes>, 'adler32': <adler32>, 'guid': <guid>, 'pfn': <pfn>}
        :param ignore_availability: A boolean to ignore blocked sites.
        :param parents_metadata: Metadata for selected hierarchy DIDs. (dictionary {'lpn': {key : value}}). Default=None
        """
        path = '/'.join([self.DIRAC_BASEURL, 'addfiles'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps({'lfns': lfns, 'ignore_availability': ignore_availability, 'parents_metadata': parents_metadata}))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
