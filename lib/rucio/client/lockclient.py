# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

from requests.status_codes import codes
from six.moves.urllib.parse import quote_plus

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class LockClient(BaseClient):

    """Lock client class for working with rucio locks"""

    LOCKS_BASEURL = 'locks'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None,
                 auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(LockClient, self).__init__(rucio_host, auth_host, account, ca_cert,
                                         auth_type, creds, timeout, user_agent, vo=vo)

    def get_dataset_locks(self, scope, name):
        """
        Get a dataset locks of the specified dataset.

        :param scope: the scope of the did of the locks to list.
        :param name: the name of the did of the locks to list.
        """

        path = '/'.join([self.LOCKS_BASEURL, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path, params={'did_type': 'dataset'})

        result = self._send_request(url)
        if result.status_code == codes.ok:   # pylint: disable-msg=E1101
            locks = self._load_json_data(result)
            return locks
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code)
            raise exc_cls(exc_msg)

    def get_dataset_locks_by_rse(self, rse):
        """
        Get all dataset locks of the specified rse.

        :param rse: the rse of the locks to list.
        """

        path = '/'.join([self.LOCKS_BASEURL, rse])
        url = build_url(choice(self.list_hosts), path=path, params={'did_type': 'dataset'})

        result = self._send_request(url)
        if result.status_code == codes.ok:   # pylint: disable-msg=E1101
            locks = self._load_json_data(result)
            return locks
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code)

            raise exc_cls(exc_msg)
