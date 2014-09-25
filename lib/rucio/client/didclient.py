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
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json, render_json_list


class DIDClient(BaseClient):

    """DataIdentifier client class for working with data identifiers"""

    DIDS_BASEURL = 'dids'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(DIDClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def list_dids(self, scope, filters, type='collection'):
        """
        List all data identifiers in a scope which match a given pattern.

        :param scope: The scope name.
        :param pattern: The wildcard pattern.
        :param type:  The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container
        :param ignore_case: Ignore case distinctions.
        :param session: The database session in use.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, 'dids', 'search'])
        payload = {}
        for k, v in filters.items():
            payload[k] = v
        payload['type'] = type

        url = build_url(choice(self.list_hosts), path=path, params=payload)

        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            dids = self._load_json_data(r)
            return dids
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def add_did(self, scope, name, type, statuses=None, meta=None, rules=None, lifetime=None):
        """
        Add data identifier for a dataset or container.

        :param scope: The scope name.
        :param name: The data identifier name.
        :paran type: The data identifier type (file|dataset|container).
        :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
        :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        :param lifetime: DID's lifetime (in seconds).
        """
        path = '/'.join([self.DIDS_BASEURL, scope, name])
        url = build_url(choice(self.list_hosts), path=path)
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

    def add_dids(self, dids):
        """
        Buld add datasets/containers.
        """
        path = '/'.join([self.DIDS_BASEURL])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='POST', data=render_json_list(dids))
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
        return self.add_did(scope=scope, name=name, type='DATASET', statuses=statuses, meta=meta, rules=rules, lifetime=lifetime)

    def add_datasets(self, dsns):
        """
        Bulk add datasets.

        :param dsns: A list of datasets.
        """
        return self.add_dids(dids=[dict(dsn.items() + [('type', 'DATASET')]) for dsn in dsns])

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
        return self.add_did(scope=scope, name=name, type='CONTAINER', statuses=statuses, meta=meta, rules=rules)

    def add_containers(self, cnts):
        """
        Bulk add containers.

        :param cnts: A list of containers.
        """
        return self.add_dids(dids=[dict(cnts.items() + [('type', 'CONTAINER')]) for cnt in cnts])

    def attach_dids(self, scope, name, dids, rse=None):
        """
        Attach data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param dids: The content.
        :param rse: The RSE name when registering replicas.
        """
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'dids'])
        url = build_url(choice(self.list_hosts), path=path)
        data = {'dids': dids}
        if rse:
            data['rse'] = rse
        r = self._send_request(url, type='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def detach_dids(self, scope, name, dids):
        """
        Detach data identifier

        :param scope: The scope name.
        :param name: The data identifier name.
        :param dids: The content.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'dids'])
        url = build_url(choice(self.list_hosts), path=path)
        data = {'dids': dids}
        r = self._send_request(url, type='DEL', data=render_json(**data))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def attach_dids_to_dids(self, attachments):
        """
        Add dids to dids.

        :param attachments: The attachments.
        """
        path = '/'.join([self.DIDS_BASEURL, 'attachments'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='POST', data=render_json_list(attachments))
        if r.status_code in (codes.ok, codes.no_content, codes.created):
            return True

        exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
        raise exc_cls(exc_msg)

    def add_files_to_datasets(self, attachments):
        """
        Add files to datasets.

        :param attachments: The attachments.
        """
        return self.attach_dids_to_dids(attachments=attachments)

    def add_datasets_to_containers(self, attachments):
        """
        Add datasets_to_containers.

        :param attachments: The attachments.
        """
        return self.attach_dids_to_dids(attachments=attachments)

    def add_containers_to_containers(self, attachments):
        """
        Add containers_to_containers.

        :param attachments: The attachments.
        """
        return self.attach_dids_to_dids(attachments=attachments)

    def add_files_to_dataset(self, scope, name, files, rse=None):
        """
        Add files to datasets.

        :param scope: The scope name.
        :param name: The dataset name.
        :param files: The content.
        :param rse: The RSE name when registering replicas.
        """
        return self.attach_dids(scope=scope, name=name, dids=files, rse=rse)

    def add_datasets_to_container(self, scope, name, dsns):
        """
        Add datasets to container.

        :param scope: The scope name.
        :param name: The dataset name.
        :param dsns: The content.
        """
        return self.attach_dids(scope=scope, name=name, dids=dsns)

    def add_containers_to_container(self, scope, name, cnts):
        """
        Add containers to container.

        :param scope: The scope name.
        :param name: The dataset name.
        :param dsns: The content.
        """
        return self.attach_dids(scope=scope, name=name, dids=cnts)

    def list_content(self, scope, name):
        """
        List data identifier contents.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'dids'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_files(self, scope, name, long=None):
        """
        List data identifier file contents.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param long: A boolean to choose if GUID is returned or not.
        """

        payload = {}
        path = '/'.join([self.DIDS_BASEURL, scope, name, 'files'])
        if long:
            payload['long'] = True
        url = build_url(choice(self.list_hosts), path=path, params=payload)

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
        url = build_url(choice(self.list_hosts), path=path, params=payload)

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
        url = build_url(choice(self.list_hosts), path=path)
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
        url = build_url(choice(self.list_hosts), path=path)
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
        url = build_url(choice(self.list_hosts), path=path)
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
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps(kwargs)
        r = self._send_request(url, type='PUT', data=data)
        if r.status_code in (codes.ok, codes.no_content, codes.created):
            return True

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
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
            raise exc_cls(exc_msg)

    def list_did_rules(self, scope, name):
        """
        List the associated rules of a data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, scope, name, 'rules'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)
