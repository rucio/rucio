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

#
# Author(s):
# - Anil Panta <anilpanta2@gmail.con>, 2023

'''
 Elasticsearch based metadata plugin.
'''

import datetime
import operator
from typing import Any, TYPE_CHECKING, Optional, Union

from elasticsearch import Elasticsearch
from elasticsearch import exceptions as elastic_exceptions

from rucio.common import config, exception
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalScope

IMMUTABLE_KEYS = [
    'scope',            # generated on insert
    'name',             # generated on insert
    'vo'                # generated on insert
]


class ElasticDidMeta(DidMetaPlugin):
    def __init__(
        self,
        hosts: "Optional[list[str]]" = None,
        user: "Optional[str]" = None,
        password: "Optional[str]" = None,
        index: "Optional[str]" = None,
        archive_index: "Optional[str]" = None,
        use_ssl: "Optional[bool]" = False,
        verify_certs: bool = True,
        ca_certs: "Optional[str]" = None,
        client_cert: "Optional[str]" = None,
        client_key: "Optional[str]" = None,
        request_timeout: int = 100,
        max_retries: int = 3,
        retry_on_timeout: bool = False
    ) -> None:
        super(ElasticDidMeta, self).__init__()
        hosts = hosts or [config.config_get('metadata', 'elastic_service_host')]
        user = user or config.config_get('metadata', 'elastic_user', False, None)
        password = password or config.config_get('metadata', 'elastic_password', False, None)
        self.index = index or config.config_get('metadata', 'meta_index', False, 'rucio_did_meta')
        self.archive_index = archive_index or config.config_get('metadata', 'archive_index', False, 'archive_meta')
        use_ssl = use_ssl or bool(config.config_get('metadata', 'use_ssl', False, False))
        ca_certs = ca_certs or config.config_get('metadata', 'ca_certs', False, None)
        client_cert = client_cert or config.config_get('metadata', 'client_cert', False, None)
        client_key = client_key or config.config_get('metadata', 'client_key', False, None)

        self.es_config = {
            'hosts': hosts,
            'timeout': request_timeout,
            'max_retries': max_retries,
            'retry_on_timeout': retry_on_timeout
        }
        if user and password:
            self.es_config['basic_auth'] = (user, password)

        if use_ssl:
            self.es_config.update({
                'ca_certs': ca_certs,
                'verify_certs': verify_certs,
            })
            if client_cert and client_key:
                self.es_config.update({
                    'client_cert': client_cert,
                    'client_key': client_key
                })

        self.client = Elasticsearch(**self.es_config)
        self.plugin_name = "ELASTIC"

    def drop_index(self) -> None:
        self.client.indices.delete(index=self.index)

    def get_metadata(
        self,
        scope: "InternalScope",
        name: str,
        *,
        session: "Optional[Session]" = None
    ) -> dict[str, Any]:
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: The metadata for the did
        :raises DataIdentifierNotFound: If the DID metadata is not found.
        :raises RucioException: If another error occurs during the process.
        """

        doc_id = f"{scope.internal}{name}"
        try:
            doc = self.client.get(index=self.index, id=doc_id)["_source"]
        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)
        return doc

    def set_metadata(
        self,
        scope: "InternalScope",
        name: str,
        key: str,
        value: str,
        recursive: bool = False,
        *,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Set single metadata key.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be added
        :param value: the value of the key to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        self.set_metadata_bulk(scope=scope, name=name, meta={key: value}, recursive=recursive, session=session)

    def set_metadata_bulk(
        self,
        scope: "InternalScope",
        name: str,
        meta: dict[str, Any],
        recursive: bool = False,
        *,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Bulk set metadata keys.

        :param scope: the scope of did
        :param name: the name of the did
        :param meta: dictionary of metadata keypairs to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        doc_id = f"{scope.internal}{name}"
        try:
            # Try to get existing metadata
            existing_meta = self.get_metadata(scope, name)
        except exception.DataIdentifierNotFound:
            existing_meta = {
                'scope': str(scope.external),
                'name': str(name),
                'vo': str(scope.vo)
            }
        for key, value in meta.items():
            if key not in IMMUTABLE_KEYS:
                existing_meta[key] = value

        try:
            self.client.index(index=self.index, body=existing_meta, id=doc_id, refresh="true")
        except Exception as err:
            raise exception.RucioException(err)

    def delete_metadata(
        self,
        scope: "InternalScope",
        name: str,
        key: str,
        *,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Delete a key from metadata.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        doc_id = f"{scope.internal}{name}"
        try:
            # First, get the current document
            doc = self.client.get(index=self.index, id=doc_id)

            # Check if the key exists in the document
            if key in doc['_source']:
                # Use script to remove the field
                script = {
                    "script": {
                        "source": f"ctx._source.remove('{key}')",
                        "lang": "painless"
                    }
                }
                self.client.update(index=self.index, id=doc_id, body=script)
        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)

    def list_dids(
        self,
        scope: "InternalScope",
        filters: Union[list[dict[str, Any]], dict[str, Any]],
        did_type: str = 'collection',
        ignore_case: bool = False,
        limit: "Optional[int]" = None,
        offset: "Optional[int]" = None,
        long: bool = False,
        recursive: bool = False,
        ignore_dids: "Optional[list]" = None,
        *,
        session: "Optional[Session]" = None
    ) -> "Iterator[dict[str, Any]]":
        """
        List DIDs (Data Identifier).

        :param scope: The scope of the DIDs to search.
        :param filters: The filters to apply to the DID search.
        :param did_type: The type of DID (default is 'collection').
        :param ignore_case: Whether to ignore case (default is False).
        :param limit: The maximum number of DIDs to return.
        :param offset: The starting point for the search (used for pagination).
        :param long: Whether to return extended information (scope, name, did_type, bytes, length) (default is False).
        :param recursive: Whether to search recursively (currently unsupported).
        :param ignore_dids: A list of DIDs to ignore (default is an empty list).
        :param session: The database session in use.
        :returns: A generator yielding DIDs as strings (when `long` is False) or dictionaries (when `long` is True).
        :raises UnsupportedOperation: If recursive searches are requested (currently unsupported).
        :raises RucioException: If an error occurs during the search.
        """

        if not ignore_dids:
            ignore_dids = []

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # Create Elasticsearch query
        fe = FilterEngine(filters, model_class=None, strict_coerce=False)
        elastic_query_str = fe.create_elastic_query(
            additional_filters=[
                ('scope', operator.eq, str(scope.external)),
                ('vo', operator.eq, str(scope.vo))
            ]
        )
        pit = self.client.open_point_in_time(index=self.index, keep_alive="2m")
        pit_id = pit["id"]
        # Base query with point in time(pit) paramter.
        # sort is needed for search_after, so we use scope sort (random choice)
        query = {
            "query": elastic_query_str,
            "sort": [{"scope.keyword": "asc"}],
            "_source": ["scope", "name"] if not long else ["scope", "name", "did_type", "bytes", "length"],
            "pit": {"id": pit_id, "keep_alive": "2m"}
        }

        # Add sorting and pagination
        if offset:
            query["from"] = offset
        size = limit if limit else 10000
        query["size"] = size
        search_after = None
        total_processed = 0
        try:
            while True:
                if search_after:
                    query["search_after"] = search_after
                    query.pop("from", None)
                # Execute search
                results = self.client.search(body=query)
                hits = results['hits']['hits']
                if not hits:
                    break

                for hit in hits:
                    did_full = f"{hit['_source']['scope']}:{hit['_source']['name']}"
                    if did_full not in ignore_dids:
                        ignore_dids.append(did_full)
                        if long:
                            yield {
                                'scope': (hit['_source']['scope']),
                                'name': hit['_source']['name'],
                                'did_type': hit['_source'].get('did_type', 'N/A'),
                                'bytes': hit['_source'].get('bytes', 'N/A'),
                                'length': hit['_source'].get('length', 'N/A')
                            }
                        else:
                            yield hit['_source']['name']

                    total_processed += 1
                    if limit and total_processed >= limit:
                        break

                # Update search_after for the next iteration
                search_after = hits[-1]["sort"]

        finally:
            # Always delete the point in time when done
            self.client.close_point_in_time(body={"id": pit_id})

        if recursive:
            raise exception.UnsupportedOperation(f"'{self.plugin_name.lower()}' metadata module does not currently support recursive searches")

    def on_delete(
        self,
        scope: "InternalScope",
        name: str,
        archive: bool = False,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Delete a document and optionally archive it.

        :param scope: The scope of the document
        :param name: The name of the document
        :param archive: Whether to archive the document before deletion
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        doc_id = f"{scope}{name}"

        try:
            doc = self.client.get(index=self.index, id=doc_id)

            if archive:
                archived_doc = doc['_source']
                archived_doc['deleted_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self.client.index(index=self.archive_index, id=doc_id, body=archived_doc)

            self.client.delete(index=self.index, id=doc_id)

        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)

    def get_metadata_archived(
        self,
        scope: "InternalScope",
        name: str,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Retrieve archived metadata for a given scope and name.

        :param scope: The scope of the document
        :param name: The name of the document
        :return: The archived metadata or None if not found
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        doc_id = f"{scope}{name}"

        try:
            doc = self.client.get(index=self.archive_index, id=doc_id)["_source"]
            return doc
        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)

    def manages_key(
        self,
        key: str,
        *,
        session: "Optional[Session]" = None
    ) -> bool:
        return True

    def get_plugin_name(self) -> str:
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name
