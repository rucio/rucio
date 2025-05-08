# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
from json import dumps
from typing import TYPE_CHECKING, Any, Literal, Optional, Union
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.exception import DeprecationError
from rucio.common.utils import build_url, date_to_str, render_json

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence


class DIDClient(BaseClient):

    """DataIdentifier client class for working with data identifiers"""

    DIDS_BASEURL = 'dids'
    ARCHIVES_BASEURL = 'archives'

    def list_dids(
            self,
            scope: str,
            filters: "Sequence[dict[str, Any]]",
            did_type: Literal['all', 'collection', 'dataset', 'container', 'file'] = 'collection',
            long: bool = False,
            recursive: bool = False
    ) -> "Iterator[dict[str, Any]]":
        """
        List all data identifiers in a scope which match a given pattern.

        Parameters
        ----------
            scope :
                The scope name.
            filters :
                A nested dictionary of key/value pairs like [{'key1': 'value1', 'key2.lte': 'value2'}, {'key3.gte, 'value3'}].
                Keypairs in the same dictionary are AND'ed together, dictionaries are OR'ed together. Keys should be suffixed
                like <key>.<operation>, e.g. key1 >= value1 is equivalent to {'key1.gte': value}, where <operation> belongs to one
                of the set {'lte', 'gte', 'gt', 'lt', 'ne' or ''}. Equivalence doesn't require an operator.
            did_type :
                The type of the did: 'all'(container, dataset or file)|'collection'(dataset or container)|'dataset'|'container'|'file'
            long :
                Long format option to display more information for each DID.
            recursive :
                Recursively list DIDs content.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), 'dids', 'search'])

        # stringify dates.
        if isinstance(filters, dict):   # backwards compatibility for filters as single {}
            filters = [filters]
        for or_group in filters:
            for key, value in or_group.items():
                if isinstance(value, datetime):
                    or_group[key] = date_to_str(value)

        payload = {
            'type': did_type,
            'filters': filters,
            'long': long,
            'recursive': recursive
        }

        url = build_url(choice(self.list_hosts), path=path, params=payload)

        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            dids = self._load_json_data(r)
            return dids
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_dids_extended(self, scope, filters, did_type='collection', long=False, recursive=False):
        """
        List all data identifiers in a scope which match a given pattern (DEPRECATED)
        """
        raise DeprecationError("Command or function has been deprecated. Please use list_dids instead.")

    def add_did(
            self,
            scope: str,
            name: str,
            did_type: Literal['DATASET', 'CONTAINER'],
            statuses: Optional["Mapping[str, Any]"] = None,
            meta: Optional["Mapping[str, Any]"] = None,
            rules: Optional["Sequence[Mapping[str, Any]]"] = None,
            lifetime: Optional[int] = None,
            dids: Optional["Sequence[Mapping[str, Any]]"] = None,
            rse: Optional[str] = None
    ) -> bool:
        """
        Add data identifier for a dataset or container.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        did_type :
            The data identifier type (dataset|container).
        statuses :
            Dictionary with statuses, e.g. {'monotonic':True}.
        meta :
            Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        rules :
            Replication rules associated with the data identifier. A list of dictionaries,
            e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        lifetime :
            DID's lifetime (in seconds).
        dids :
            The content.
        rse :
            The RSE name when registering replicas.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)
        # Build json
        data: dict[str, Any] = {'type': did_type}
        if statuses:
            data['statuses'] = statuses
        if meta:
            data['meta'] = meta
        if rules:
            data['rules'] = rules
        if lifetime:
            data['lifetime'] = lifetime
        if dids:
            data['dids'] = dids
        if rse:
            data['rse'] = rse
        r = self._send_request(url, type_='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_dids(self, dids: "Sequence[Mapping[str, Any]]") -> bool:
        """
        Bulk add datasets/containers.
        """
        path = '/'.join([self.DIDS_BASEURL])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=render_json(dids))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_dataset(
            self,
            scope: str,
            name: str,
            statuses: Optional["Mapping[str, Any]"] = None,
            meta: Optional["Mapping[str, Any]"] = None,
            rules: Optional["Sequence[Mapping[str, Any]]"] = None,
            lifetime: Optional[int] = None,
            files: Optional["Sequence[Mapping[str, Any]]"] = None,
            rse: Optional[str] = None
    ) -> bool:
        """
        Add data identifier for a dataset.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        statuses :
            Dictionary with statuses, e.g. {'monotonic':True}.
        meta :
            Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        rules :
            Replication rules associated with the data identifier. A list of dictionaries,
            e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        lifetime :
            DID's lifetime (in seconds).
        files :
            The content.
        rse :
            The RSE name when registering replicas.
        """
        return self.add_did(scope=scope, name=name, did_type='DATASET',
                            statuses=statuses, meta=meta, rules=rules,
                            lifetime=lifetime, dids=files, rse=rse)

    def add_datasets(self, dsns: "Iterable[dict[str, Any]]") -> bool:
        """
        Bulk add datasets.

        Parameters
        ----------
        dsns :
            A list of datasets.
        """
        return self.add_dids(dids=[dict(list(dsn.items()) + [('type', 'DATASET')]) for dsn in dsns])

    def add_container(
            self,
            scope: str,
            name: str,
            statuses: Optional["Mapping[str, Any]"] = None,
            meta: Optional["Mapping[str, Any]"] = None,
            rules: Optional["Sequence[Mapping[str, Any]]"] = None,
            lifetime: Optional[int] = None
    ) -> bool:
        """
        Add data identifier for a container.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        statuses :
            Dictionary with statuses, e.g. {'monotonic':True}.
        meta :
            Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
        rules :
            Replication rules associated with the data identifier. A list of dictionaries,
            e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
        lifetime :
            DID's lifetime (in seconds).
        """
        return self.add_did(scope=scope, name=name, did_type='CONTAINER', statuses=statuses, meta=meta, rules=rules, lifetime=lifetime)

    def add_containers(self, cnts: "Sequence[dict[str, Any]]") -> bool:
        """
        Bulk add containers.

        Parameters
        ----------
        cnts :
            A list of containers.
        """
        return self.add_dids(dids=[dict(list(cnt.items()) + [('type', 'CONTAINER')]) for cnt in cnts])

    def attach_dids(
            self,
            scope: str,
            name: str,
            dids: "Sequence[Mapping[str, Any]]",
            rse: Optional[str] = None
    ) -> bool:
        """
        Attach data identifier.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        dids :
            The content.
        rse :
            The RSE name when registering replicas.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'dids'])
        url = build_url(choice(self.list_hosts), path=path)
        data: dict[str, Any] = {'dids': dids}
        if rse:
            data['rse'] = rse
        r = self._send_request(url, type_='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def detach_dids(
            self,
            scope: str,
            name: str,
            dids: Optional["Sequence[Mapping[str, Any]]"] = None
    ) -> bool:
        """
        Detach data identifier.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        dids :
            The content.
        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'dids'])
        url = build_url(choice(self.list_hosts), path=path)
        data = {'dids': dids}
        r = self._send_request(url, type_='DEL', data=render_json(**data))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def attach_dids_to_dids(
            self,
            attachments: "Sequence[dict[str, Union[str, Sequence[dict[str, Any]]]]]",
            ignore_duplicate: bool = False
    ) -> bool:
        """
        Add dids to dids.

        Parameters
        ----------
        attachments :
            The attachments.
            An attachment contains: "scope", "name", "dids".
            dids is: [{'scope': scope, 'name': name}, ...]
        ignore_duplicate :
            If True, ignore duplicate entries.
        """
        path = '/'.join([self.DIDS_BASEURL, 'attachments'])
        url = build_url(choice(self.list_hosts), path=path)
        data = {'ignore_duplicate': ignore_duplicate, 'attachments': attachments}
        r = self._send_request(url, type_='POST', data=dumps(data))
        if r.status_code in (codes.ok, codes.no_content, codes.created):
            return True

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def add_files_to_datasets(
            self,
            attachments: "Sequence[dict[str, Union[str, Sequence[dict[str, Any]]]]]",
            ignore_duplicate: bool = False
    ) -> bool:
        """
        Add files to datasets.

        Parameters
        ----------
        attachments :
            The attachments.
            An attachment contains: "scope", "name", "dids".
            dids is: [{'scope': scope, 'name': name}, ...]
        ignore_duplicate :
            If True, ignore duplicate entries.
        """
        return self.attach_dids_to_dids(attachments=attachments,
                                        ignore_duplicate=ignore_duplicate)

    def add_datasets_to_containers(
            self,
            attachments: "Sequence[dict[str, Union[str, Sequence[dict[str, Any]]]]]"
    ) -> bool:
        """
        Add datasets_to_containers.

        Parameters
        ----------
        attachments :
            The attachments.
            An attachment contains: "scope", "name", "dids".
            dids is: [{'scope': scope, 'name': name}, ...]
        """
        return self.attach_dids_to_dids(attachments=attachments)

    def add_containers_to_containers(
            self,
            attachments: "Sequence[dict[str, Union[str, Sequence[dict[str, Any]]]]]"
    ) -> bool:
        """
        Add containers_to_containers.

        Parameters
        ----------
        attachments :
            The attachments.
            An attachment contains: "scope", "name", "dids".
            dids is: [{'scope': scope, 'name': name}, ...]
        """
        return self.attach_dids_to_dids(attachments=attachments)

    def add_files_to_dataset(
            self,
            scope: str,
            name: str,
            files: "Sequence[Mapping[str, Any]]",
            rse: Optional[str] = None
    ) -> bool:
        """
        Add files to datasets.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The dataset name.
        files :
            The content.
        rse :
            The RSE name when registering replicas.
        """
        return self.attach_dids(scope=scope, name=name, dids=files, rse=rse)

    def add_files_to_archive(
            self,
            scope: str,
            name: str,
            files: "Sequence[Mapping[str, Any]]"
    ) -> bool:
        """
        Add files to archive.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The dataset name.
        files :
            The content.
        """
        return self.attach_dids(scope=scope, name=name, dids=files)

    def add_datasets_to_container(
            self,
            scope: str,
            name: str,
            dsns: "Sequence[Mapping[str, Any]]"
    ) -> bool:
        """
        Add datasets to container.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The dataset name.
        dsns :
            The content.
        """
        return self.attach_dids(scope=scope, name=name, dids=dsns)

    def add_containers_to_container(
            self,
            scope: str,
            name: str,
            cnts: "Sequence[Mapping[str, Any]]"
    ) -> bool:
        """
        Add containers to container.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The dataset name.
        cnts :
            The content.
        """
        return self.attach_dids(scope=scope, name=name, dids=cnts)

    def list_content(
        self,
        scope: str,
        name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List data identifier contents.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'dids'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_content_history(
            self,
            scope: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List data identifier contents history.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.

        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'dids', 'history'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_files(
            self,
            scope: str,
            name: str,
            long: Optional[bool] = None
    ) -> "Iterator[dict[str, Any]]":
        """
        List data identifier file contents.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        long :
            A boolean to choose if GUID is returned or not.
        """

        payload = {}
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'files'])
        if long:
            payload['long'] = True
        url = build_url(choice(self.list_hosts), path=path, params=payload)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def bulk_list_files(self, dids: list[dict[str, Any]]) -> "Iterator[dict[str, Any]]":
        """
        List data identifier file contents.

        Parameters
        ----------
        dids :
            The list of DIDs.
        """

        data = {'dids': dids}
        path = '/'.join([self.DIDS_BASEURL, 'bulkfiles'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='POST', data=dumps(data), stream=True)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_did(
            self,
            scope: str,
            name: str,
            dynamic: bool = False,
            dynamic_depth: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Retrieve a single data identifier.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        dynamic_depth :
            The DID type ('FILE'/'DATASET') at which to stop the dynamic
            length/bytes calculation. If not set, the size will not be computed dynamically.
        dynamic :
            Deprecated. Same as setting dynamic_depth='FILE'.
        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name)])
        params = {}
        if dynamic_depth:
            params['dynamic_depth'] = dynamic_depth
        elif dynamic:
            params['dynamic_depth'] = 'FILE'
        url = build_url(choice(self.list_hosts), path=path, params=params)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_metadata(
            self,
            scope: str,
            name: str,
            plugin: str = 'DID_COLUMN'
    ) -> dict[str, Any]:
        """
        Get data identifier metadata.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        plugin :
            Backend Metadata plugin the Rucio server should use to query data.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'meta'])
        url = build_url(choice(self.list_hosts), path=path)
        payload = {}
        payload['plugin'] = plugin
        r = self._send_request(url, type_='GET', params=payload)
        if r.status_code == codes.ok:
            meta = self._load_json_data(r)
            return next(meta)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_metadata_bulk(
            self,
            dids: "Sequence[Mapping[str, Any]]",
            inherit: bool = False,
            plugin: str = "JSON",
    ) -> "Iterator[dict[str, Any]]":
        """
        Bulk get data identifier metadata
        Parameters
        ----------
        dids :
            A list of dids.
        inherit :
            A boolean. If set to true, the metadata of the parent are concatenated.
        plugin :
            The metadata plugin to query, 'ALL' for all available plugins
        """
        data = {'dids': dids, 'inherit': inherit, 'plugin': plugin}
        path = '/'.join([self.DIDS_BASEURL, 'bulkmeta'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps(data))
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def set_metadata(
            self,
            scope: str,
            name: str,
            key: str,
            value: Any,
            recursive: bool = False
    ) -> bool:
        """
        Set data identifier metadata.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        key :
            The metadata key.
        value :
            The metadata value.
        recursive :
            Option to propagate the metadata change to content.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'meta', key])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'value': value, 'recursive': recursive})
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_metadata_bulk(
            self,
            scope: str,
            name: str,
            meta: "Mapping[str, Any]",
            recursive: bool = False
    ) -> bool:
        """
        Set data identifier metadata in bulk.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        meta :
            The metadata key-value pairs.
        recursive :
            Option to propagate the metadata change to content.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'meta'])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'meta': meta, 'recursive': recursive})
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_dids_metadata_bulk(
            self,
            dids: "Sequence[Mapping[str, Any]]",
            recursive: bool = False
    ) -> bool:
        """
        Set metadata to a list of data identifiers.

        Parameters
        ----------
        dids :
            A list of dids including metadata, i.e.
            [{'scope': scope1, 'name': name1, 'meta': {key1: value1, key2: value2}}, ...].
        recursive :
            Option to propagate the metadata update to content.
        """
        path = '/'.join([self.DIDS_BASEURL, 'bulkdidsmeta'])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'dids': dids, 'recursive': recursive})
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_status(
            self,
            scope: str,
            name: str,
            **kwargs
    ) -> bool:
        """
        Set data identifier status.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        **kwargs
            Keyword arguments of the form status_name=value.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'status'])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps(kwargs)
        r = self._send_request(url, type_='PUT', data=data)
        if r.status_code in (codes.ok, codes.no_content, codes.created):
            return True

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def close(
            self,
            scope: str,
            name: str
    ) -> bool:
        """
        Close dataset/container.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The dataset/container name.
        """
        return self.set_status(scope=scope, name=name, open=False)

    def delete_metadata(
            self,
            scope: str,
            name: str,
            key: str
    ) -> bool:
        """
        Delete data identifier metadata.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        key :
            The metadata key to be deleted.
        """
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'meta'])
        url = build_url(choice(self.list_hosts), path=path, params={'key': key})

        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_did_rules(
            self,
            scope: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List the associated rules of a data identifier.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'rules'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_associated_rules_for_file(
            self,
            scope: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List the associated rules a file is affected from..

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'associated_rules'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_dataset_by_guid(self, guid: str) -> "Iterator[dict[str, Any]]":
        """
        Get the parent datasets for a given GUID.

        Parameters
        ----------
        guid :
            The GUID.

        Returns
        -------

            A did
        """

        path = '/'.join([self.DIDS_BASEURL, guid, 'guid'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def scope_list(
            self,
            scope: str,
            name: Optional[str] = None,
            recursive: bool = False
    ) -> "Iterator[dict[str, Any]]":
        """
        List data identifiers in a scope.

        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        recursive :
            boolean, True or False.
        """

        payload = {}
        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), ''])
        if name:
            payload['name'] = name
        if recursive:
            payload['recursive'] = True
        url = build_url(choice(self.list_hosts), path=path, params=payload)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_parent_dids(
            self,
            scope: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List parent dataset/containers of a did.

        Parameters
        ----------
        scope :
            The scope.
        name :
            The name,
        """

        path = '/'.join([self.DIDS_BASEURL, quote_plus(scope), quote_plus(name), 'parents'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def create_did_sample(
            self,
            input_scope: str,
            input_name: str,
            output_scope: str,
            output_name: str,
            nbfiles: int
    ) -> bool:
        """
        Create a sample from an input collection.

        Parameters
        ----------
        input_scope :
            The scope of the input DID.
        input_name :
            The name of the input DID.
        output_scope :
            The scope of the output dataset.
        output_name :
            The name of the output dataset.
        nbfiles :
            The number of files to register in the output dataset.
        """
        path = '/'.join([self.DIDS_BASEURL, 'sample'])
        data = dumps({
            'input_scope': input_scope,
            'input_name': input_name,
            'output_scope': output_scope,
            'output_name': output_name,
            'nbfiles': str(nbfiles)
        })
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def resurrect(self, dids: "Sequence[Mapping[str, Any]]") -> bool:
        """
        Resurrect a list of dids.

        Parameters
        ----------
        dids :
            A list of dids [{'scope': scope, 'name': name}, ...]
        """
        path = '/'.join([self.DIDS_BASEURL, 'resurrect'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps(dids))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_archive_content(
            self,
            scope: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        List archive contents.
        Parameters
        ----------
        scope :
            The scope name.
        name :
            The data identifier name.
        """
        path = '/'.join([self.ARCHIVES_BASEURL, quote_plus(scope), quote_plus(name), 'files'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
