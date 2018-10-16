# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
#
# PY3K COMPATIBLE

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class AccountLimitClient(BaseClient):

    """Account limit client class for working with account limits"""

    ACCOUNTLIMIT_BASEURL = 'accountlimits'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None,
                 auth_type=None, creds=None, timeout=600, user_agent='rucio-clients'):
        super(AccountLimitClient, self).__init__(rucio_host, auth_host, account, ca_cert,
                                                 auth_type, creds, timeout, user_agent)

    def set_account_limit(self, account, rse, bytes):
        """
        Sends the request to set an account limit for an account.

        :param account: The name of the account.
        :param rse:     The rse name.
        :param bytes:   An integer with the limit in bytes.
        :return:        True if quota was created successfully else False.
        """

        data = dumps({'bytes': bytes})
        path = '/'.join([self.ACCOUNTLIMIT_BASEURL, account, rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_account_limit(self, account, rse):
        """
        Sends the request to remove an account limit.

        :param account: The name of the account.
        :param rse:     The rse name.

        :return: True if quota was removed successfully. False otherwise.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.ACCOUNTLIMIT_BASEURL, account, rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
