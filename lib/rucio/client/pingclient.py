# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2015

from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class PingClient(BaseClient):

    """Ping client class"""

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, user_agent='rucio-clients'):
        super(PingClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def ping(self):
        """
        Sends a ping request to the rucio server.

        :return: Dictonnary with server information
        """

        headers = None
        path = 'ping'
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers=headers, type='GET')
        if r.status_code == codes.ok:
            server_info = loads(r.text)
            return server_info
