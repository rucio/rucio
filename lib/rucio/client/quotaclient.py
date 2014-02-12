# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from json import dumps
from random import choice
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class QuotaClient(BaseClient):

    """Quota client class for working with account quotas"""

    QUOTAS_BASEURL = 'quotas'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(QuotaClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def set_quota(self, account, quota):
        """
        Sends the request to set a quota for an account.

        :param account: the name of the account.
        :param quota: a string with the quota definition.
        :return: True if quota was created successfully else False.
        """

        data = dumps({'quota': quota})
        path = '/'.join([self.QUOTAS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def get_account(self, account):
        """
        Sends the request to get quota information about a given account.

        :param account: the name of the account.
        :return: a list of set quotas for the account. None if failure.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.QUOTAS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url)
        if r.status_code == codes.ok:
            tmp = self._load_json_data(r)
            return tmp.next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def delete_quota(self, account, quota):
        """
        Sends the request to remove a quota from an account.

        :param account: the name of the account.
        :param quota: a string with the quota definition.
        :return: True if quota was removed successfully. False otherwise.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.QUOTAS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
