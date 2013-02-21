# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class RSEClient(BaseClient):

    """RSE client class for working with rucio RSEs"""

    RSE_BASEURL = 'rses'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(RSEClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def add_rse(self, rse, prefix=None, deterministic=True, volatile=False):
        """
        Sends the request to create a new rse.

        :param rse: the name of the rse.
        :param prefix: the base path of the rse.
        :param deterministic: Boolean to know if the pfn is generated deterministically.
        :param volatile: Boolean for RSE cache.

        :return: True if location was created successfully else False.
        :raises Duplicate: if rse already exists.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/' + rse
        url = build_url(self.host, path=path)

        data = dumps({'prefix': prefix, 'volatile': volatile, 'deterministic': deterministic})

        r = self._send_request(url, headers, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def delete_rse(self, rse):
        """
        Sends the request to delete a rse.

        :param rse: the name of the rse.
        :return: True if location was created successfully else False.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/' + rse
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers, type='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_rses(self, filters=None):
        """
        Sends the request to list all rucio locations(RSEs).

        :filters: dict of keys & expected values to filter results

        :return: a list containing the names of all rucio locations.
        :raises AccountNotFound: if account doesn't exist.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/'
        url = build_url(self.host, path=path)

        r = self._send_request(url, headers)
        if r.status_code == codes.ok:
            accounts = loads(r.text)
            return accounts
        else:
            exc_cls, exc_msg = self._get_exception(r.text)
            raise exc_cls(exc_msg)

    def add_rse_attribute(self, rse, key, value):
        """
        Sends the request to add a RSE attribute.

        :param rse: the name of the rse.
        :param key: the attribute key.
        :param value: the attribute value.

        :return: True if RSE attribute was created successfully else False.
        :raises Duplicate: if RSE attribute already exists.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(self.host, path=path)
        data = dumps({'value': value})

        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def delete_rse_attribute(self, rse, key):
        """
        Sends the request to delete a RSE attribute.

        :param rse: the name of the rse.
        :param key: the attribute key.

        :return: True if RSE attribute was deleted successfully else False.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def list_rse_attributes(self, rse):
        """
        Sends the request to get RSE attributes.

        :param rse: the name of the rse.

        :return: True if RSE attribute was created successfully else False.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr/'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            attributes = loads(r.text)
            return attributes
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def add_file_replica(self, rse, scope, name, size, checksum, pfn=None, dsn=None):
        """
        Add a file replica to a RSE.

        :param rse: the name of the rse.
        :param scope: the name of the scope.
        :param name: the data identifier name.
        :param size: the size of the file.
        :param checksum: the checksum of the file.
        :param pfn: the physical file name for non deterministic rse.

        :param dsn: the dataset name.

        :return: True if file was created successfully else False.
        :raises Duplicate: if file replica already exists.
        """
        data = dumps({'size': size, 'checksum': checksum, 'pfn': pfn, 'dsn': dsn})
        path = '/'.join([self.RSE_BASEURL, rse, 'files', scope, name])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
