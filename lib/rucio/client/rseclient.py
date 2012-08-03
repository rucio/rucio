# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class RSEClient(BaseClient):

    """RSE client class for working with rucio RSEs"""

    def __init__(self, rucio_host=None, rucio_port=None, auth_host=None, auth_port=None, account=None, use_ssl=True, ca_cert=None, auth_type=None, creds=None):
        super(RSEClient, self).__init__(rucio_host, rucio_port, auth_host, auth_port, account, use_ssl, ca_cert, auth_type, creds)

    def create_rse(self, rse):
        """
        Sends the request to create a new rse/location.

        :param rse: the name of the  rse.
        :return: True if location was created successfully else False.
        :raises Duplicate: if location already exists.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/'
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)

        r = self._send_request(url, headers, type='POST', data=" ")

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.text)
            raise exc_cls(exc_msg)

    def list_rses(self):
        """
        Sends the request to list all rucio locations(RSEs).

        :return: a list containing the names of all rucio locations.
        :raises AccountNotFound: if account doesn't exist.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/'
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)

        r = self._send_request(url, headers)
        if r.status_code == codes.ok:
            accounts = loads(r.text)
            return accounts
        else:
            exc_cls, exc_msg = self._get_exception(r.text)
            raise exc_cls(exc_msg)
