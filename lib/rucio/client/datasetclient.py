# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class DatasetClient(BaseClient):

    """Dataset client class for working with dataset"""

    BASEURL = 'datasets'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DatasetClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def add_dataset(self, scope, dsn, meta=None):
        """
        Sends the request to create a new dataset.

        :param scope: the scope.
        :param dsn: the dsn.
        :param meta: Optional Mapping of information about the dataset.


        :return: True if account was created successfully else False.
        :raises Duplicate: if account already exists.
        """
        data = dumps({'dsn': dsn, 'meta': meta})
        path = '/'.join([self.BASEURL, scope])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def add_files_to_dataset(self, scope, dsn, lfns):
        """
        Add files to dataset.

        :param scope: the scope.
        :param dsn: the dsn.
        :param lfns: The list of lfn.

        :return: True if files were registered successfully.
        """
        data = dumps({'lfns': lfns})
        path = '/'.join([self.BASEURL, scope, dsn, 'files'])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def list_files_in_dataset(self, scope, dsn):
        """
        Sends the request to create a new dataset.

        :param scope: the scope.
        :param dsn: the dsn.


        :return: The list of files.
        """
        path = '/'.join([self.BASEURL, scope, dsn, 'files'])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='GET')

        if r.status_code == codes.ok:
            files = loads(r.text)
            return files
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
