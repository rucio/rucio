# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class DataIdentifierClient(BaseClient):

    """DataIdentifier client class for working with dataset"""

    BASEURL = 'data_ids'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DataIdentifierClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def list_replicas(self, scope, name):
        """
        List file replicas for a data_id.

        :param scope:   The scope name.
        :param dsn:     The name.

        """
        path = '/'.join([self.BASEURL, scope, name, 'rses'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            replicas = loads(r.text)
            return replicas
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add(self, scope, name, sources):
        """
        add dataset/container

        :param scope:   The scope name.
        :param dsn:     The name.
        :param sources  The content as a list of data_ids.

        """
        path = '/'.join([self.BASEURL, scope, name])
        url = build_url(self.host, path=path)
        data = dumps(sources)
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list(self, scope, name):
        """
        List dataset/container contents.

        :param scope:   The scope name.
        :param dsn:     The name.

        """
        path = '/'.join([self.BASEURL, scope, name, 'data_ids'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            data_ids = loads(r.text)
            return data_ids
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_files(self, scope, name):
        """
        List container/dataset file contents.

        :param scope:   The scope name.
        :param dsn:     The name.

        """
        path = '/'.join([self.BASEURL, scope, name, 'files'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            files = loads(r.text)
            return files
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)
