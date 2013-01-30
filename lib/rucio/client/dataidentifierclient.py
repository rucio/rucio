# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch> 2013

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class DataIdentifierClient(BaseClient):

    """DataIdentifier client class for working with data identifiers"""

    BASEURL = 'dids'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DataIdentifierClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def list_replicas(self, scope, name, protocols=None):
        """
        List file replicas for a data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param protocols: A list of protocols to filter the replicas.

        """

        payload = None
        path = '/'.join([self.BASEURL, scope, name, 'rses'])
        if protocols:
            payload = {'protocols': ','.join(protocols)}
        url = build_url(self.host, path=path, params=payload)

        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            replicas = self._load_json_data(r)
            return replicas
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add_identifier(self, scope, name, sources):
        """
        Add data identifier for a dataset or container.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param sources: The content as a list of data identifiers.
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

    def list_content(self, scope, name):
        """
        List data identifier contents.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.BASEURL, scope, name, 'dids'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            dids = self._load_json_data(r)
            return dids.next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_files(self, scope, name):
        """
        List data identifier file contents.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.BASEURL, scope, name, 'files'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            files = self._load_json_data(r)
            return files.next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def scope_list(self, scope):
        """
        List data identifiers in scope.

        :param scope: The scope name.
        """

        path = '/'.join([self.BASEURL, scope, ''])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            dids = self._load_json_data(r)
            return dids
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def get_did(self, scope, name):
        """
        Retrieve a single data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.BASEURL, scope, name])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            did = self._load_json_data(r)
            return did.next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def get_metadata(self, scope, name):
        """
        Get data identifier metadata

        :param scope: The scope name.
        :param name: The data identifier name.
        """
        path = '/'.join([self.BASEURL, scope, name, 'meta'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            meta = self._load_json_data(r)
            return meta.next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def set_metadata(self, scope, name, key, value):
        """
        Set data identifier metadata

        :param scope: The scope name.
        :param name: The data identifier name.
        :param key: the key.
        :param value: the value.
        """
        path = '/'.join([self.BASEURL, scope, name, 'meta', key])
        url = build_url(self.host, path=path)
        data = dumps({'value': value})
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def set_status(self, scope, name, **kwargs):
        """
        Set data identifier status

        :param scope: The scope name.
        :param name: The data identifier name.
        :param kwargs:  Keyword arguments of the form status_name=value.
        """
        path = '/'.join([self.BASEURL, scope, name, 'status'])
        url = build_url(self.host, path=path)
        data = dumps(kwargs)
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code == codes.ok or r.status_code == codes.no_content:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def delete_metadata(self, scope, name, key):
        """
        Delete data identifier metadata

        :param scope: The scope name.
        :param name: The data identifier.
        :param key: the key.
        """
        path = '/'.join([self.BASEURL, scope, name, 'meta', key])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
