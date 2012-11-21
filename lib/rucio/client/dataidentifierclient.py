# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class DataIdentifierClient(BaseClient):

    """DataIdentifier client class for working with data identifiers"""

    BASEURL = 'ids'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DataIdentifierClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def list_replicas(self, scope, did):
        """
        List file replicas for a data identifier.

        :param scope: The scope name.
        :param did: The data identifier.
        """

        path = '/'.join([self.BASEURL, scope, did, 'rses'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            replicas = loads(r.text)
            return replicas
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add_identifier(self, scope, did, sources):
        """
        Add data identifier for a dataset or container.

        :param scope: The scope name.
        :param did: The data identifier.
        :param sources: The content as a list of data identifiers.
        """

        path = '/'.join([self.BASEURL, scope, did])
        url = build_url(self.host, path=path)
        data = dumps(sources)
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_content(self, scope, did):
        """
        List data identifier contents.

        :param scope: The scope name.
        :param did: The data identifier.

        """
        path = '/'.join([self.BASEURL, scope, did, 'dids'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            data_ids = loads(r.text)
            return data_ids
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_files(self, scope, did):
        """
        List data identifier file contents.

        :param scope: The scope name.
        :param did: The data identifier.

        """
        path = '/'.join([self.BASEURL, scope, did, 'files'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            files = loads(r.text)
            return files
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)
