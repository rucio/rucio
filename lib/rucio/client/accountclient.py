# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012


"""
Client classes for callers of the Rucio system
"""

import json
import requests

from rucio.client import Client
from rucio.common.exception import RucioException
from rucio.common.utils import build_url


class AccountClient(Client):

    """Account client class for working with rucio accounts"""

    def __init__(self, host, port=None, account=None, use_ssl=False, auth_type=None, creds=None, debug=False):
        super(AccountClient, self).__init__(host, port, account, use_ssl, auth_type, creds, debug)

    def create_account(self, accountName):
        """
        sends the request to create a new account.

        :param accountName: the name of the account.
        :return: True if account was created successfully else False.
        """

        headers = {'Rucio-Account': self.account, 'Rucio-Auth-Token': self.auth_token, 'Rucio-Type': 'user'}
        path = 'account/' + accountName
        url = build_url(self.host, path=path)

        r = requests.post(url, headers=headers, data=" ")

        if r.status_code == requests.codes.created:
            return True
        else:
            raise RucioException(r.text)

    def get_account(self, accountName):
        """
        sends the request to get information about a given account.

        :param accountName: the name of the account.
        :return: a list of attributes for the account. None if failure.
        """

        headers = {'Rucio-Account': self.account, 'Rucio-Auth-Token': self.auth_token}
        path = 'account/' + accountName
        url = build_url(self.host, path=path)
        r = requests.get(url, headers=headers)

        if r.status_code == requests.codes.ok:
            acc = json.loads(r.text)
            return acc
        else:
            print self.auth_token
            raise RucioException(r.text)
