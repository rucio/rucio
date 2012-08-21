# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import loads
from requests import get
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class PingClient(BaseClient):

    """Ping client class"""

    def __init__(self, rucio_host=None, rucio_port=None, auth_host=None, auth_port=None, account=None, rucio_use_ssl=True, auth_use_ssl=True, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(PingClient, self).__init__(rucio_host, rucio_port, auth_host, auth_port, account, rucio_use_ssl, auth_use_ssl, ca_cert, auth_type, creds)

    def ping(self):
        """
        Sends a ping request to the rucio server.

        :return: Dictonnary with server information
        """

        headers = None
        path = '/'
        url = build_url(self.host, path=path, use_ssl=False)
        r = get(url, headers=headers)
        if r.status_code == codes.ok:
            server_info = loads(r.text)
            return server_info
