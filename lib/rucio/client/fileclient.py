# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2015

from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class FileClient(BaseClient):
    """Dataset client class for working with dataset"""

    BASEURL = 'files'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, user_agent='rucio-clients'):
        """ Constructor """
        super(FileClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def list_file_replicas(self, scope, lfn):
        """
        List file replicas.

        :param scope: the scope.
        :param lfn: the lfn.

        :return: List of replicas.
        """
        path = '/'.join([self.BASEURL, scope, lfn, 'rses'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='GET')

        if r.status_code == codes.ok:
            rses = loads(r.text)
            return rses
        else:
            print r.status_code
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
