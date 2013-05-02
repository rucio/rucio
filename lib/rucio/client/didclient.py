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
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2013

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url, render_json


class DIDClient(BaseClient):

    """DataIdentifier client class for working with data identifiers"""

    DIDS_BASEURL = 'dids'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DIDClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def list_replicas(self, scope, name, schemes=None):
        """
        List file replicas for a data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param schemes: A list of schemes to filter the replicas.

        """

        payload = None
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'rses'])
        if schemes:
            payload = {'schemes': ','.join(schemes)}
        url = build_url(self.host, path=path, params=payload)

        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            replicas = self._load_json_data(r)
            return replicas
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add_identifier(self, scope, name, type, statuses=None, meta=None, rules=None, lifetime=None):
        """
        Add data identifier for a data@transactional_sessionset or container.

        :param scope: The scope name.
        :param name: The data identifier name.
        :paran type: The data identifier type (file|dataset|container).
        :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
        :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        :param lifetime: DID's lifetime (in seconds).
        """
        path = '/'.join([self.DIDS_BASEURL, scope, name])
        url = build_url(self.host, path=path)
        # Build json
        data = {'type': type}
        if statuses:
            data['statuses'] = statuses
        if meta:
            data['meta'] = meta
        if rules:
            data['rules'] = rules
        if lifetime:
            data['lifetime'] = lifetime
        r = self._send_request(url, type='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add_dataset(self, scope, name, statuses=None, meta=None, rules=None, lifetime=None):
        """
        Add data identifier for a dataset.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
        :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        :param lifetime: DID's lifetime (in seconds).
        """
        return self.add_identifier(scope=scope, name=name, type='dataset', statuses=statuses, meta=meta, rules=rules, lifetime=lifetime)

    def add_container(self, scope, name, statuses=None, meta=None, rules=None, lifetime=None):
        """
        Add data identifier for a container.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
        :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        :param lifetime: DID's lifetime (in seconds).
        """
        return self.add_identifier(scope=scope, name=name, type='container', statuses=statuses, meta=meta, rules=rules)

    def attach_identifier(self, scope, name, dids):
        """
        Attach data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param dids: The content.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'dids'])
        url = build_url(self.host, path=path)
        data = {'dids': dids}
        r = self._send_request(url, type='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def detach_identifier(self, scope, name, dids):
        """
        Detach data identifier

        :param scope: The scope name.
        :param name: The data identifier name.
        :param dids: The content.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'dids'])
        url = build_url(self.host, path=path)
        data = {'dids': dids}
        r = self._send_request(url, type='DEL', data=render_json(**data))
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add_files_to_dataset(self, scope, name, files):
        """
        Add files to datasets.

        :param scope: The scope name.
        :param name: The dataset name.
        :param files: The content.
        """
        return self.attach_identifier(scope=scope, name=name, dids=files)

    def add_datasets_to_container(self, scope, name, dsns):
        """
        Add datasets to container.

        :param scope: The scope name.
        :param name: The dataset name.
        :param dsns: The content.
        """
        return self.attach_identifier(scope=scope, name=name, dids=dsns)

    def add_containers_to_container(self, scope, name, cnts):
        """
        Add containers to container.

        :param scope: The scope name.
        :param name: The dataset name.
        :param dsns: The content.
        """
        return self.attach_identifier(scope=scope, name=name, dids=cnts)

    def list_content(self, scope, name):
        """
        List data identifier contents.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'dids'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_files(self, scope, name):
        """
        List data identifier file contents.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'files'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def scope_list(self, scope, name=None, recursive=False):
        """
        List data identifiers in a scope.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param recursive: boolean, True or False.
        """

        payload = {}
        path = '/'.join([self.DIDS_BASEURL, scope, ''])
        if name:
            payload['name'] = name
        if recursive:
            payload['recursive'] = True
        url = build_url(self.host, path=path, params=payload)

        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def get_did(self, scope, name):
        """
        Retrieve a single data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r).next()
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def get_metadata(self, scope, name):
        """
        Get data identifier metadata

        :param scope: The scope name.
        :param name: The data identifier name.
        """
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'meta'])
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
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'meta', key])
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
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'status'])
        url = build_url(self.host, path=path)
        data = dumps(kwargs)
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code == codes.ok or r.status_code == codes.no_content:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def close(self, scope, name):
        """
        close dataset/container

        :param scope: The scope name.
        :param name: The dataset/container name.
        """
        return self.set_status(scope=scope, name=name, open=False)

    def delete_metadata(self, scope, name, key):
        """
        Delete data identifier metadata

        :param scope: The scope name.
        :param name: The data identifier.
        :param key: the key.
        """
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'meta', key])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
