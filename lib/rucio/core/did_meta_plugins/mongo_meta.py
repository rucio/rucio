# -*- coding: utf-8 -*-
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

import operator

import pymongo

from rucio.common import config
from rucio.common import exception
from rucio.common.types import InternalScope
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine

IMMUTABLE_KEYS = [
    '_id',              # index key
    'scope',            # generated on insert
    'name',             # generated on insert
    'vo'                # generated on insert
]


class MongoDidMeta(DidMetaPlugin):
    def __init__(self, host=None, port=None, db=None, collection=None):
        super(MongoDidMeta, self).__init__()
        if host is None:
            host = config.config_get('metadata', 'mongo_service_host')
        if port is None:
            port = config.config_get('metadata', 'mongo_service_port')
        if db is None:
            db = config.config_get('metadata', 'mongo_db')
        if collection is None:
            collection = config.config_get('metadata', 'mongo_collection')

        self.client = pymongo.MongoClient("mongodb://{}:{}/".format(host, port))
        self.db = self.client[db]
        self.col = self.db[collection]

        self.plugin_name = "MONGO"

    def drop_database(self):
        self.client.drop_database(self.db.name)

    def get_metadata(self, scope, name, session=None):
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: The metadata for the did
        """
        # get first document with this did == _id
        doc = self.col.find_one({
            "_id": "{}:{}".format(scope.internal, name)
        })

        # pop immutable keys
        for key in IMMUTABLE_KEYS:
            if key in doc:
                doc.pop(key)

        if not doc:
            raise exception.DataIdentifierNotFound("No metadata found for did '%(scope)s:%(name)s'" % locals())
        return doc

    def set_metadata(self, scope, name, key, value, recursive=False, session=None):
        """
        Set single metadata key.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be added
        :param value: the value of the key to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        """
        self.set_metadata_bulk(scope=scope, name=name, meta={key: value}, recursive=recursive, session=session)

    def set_metadata_bulk(self, scope, name, meta, recursive=False, session=None):
        """
        Bulk set metadata keys.

        :param scope: the scope of did
        :param name: the name of the did
        :param meta: dictionary of metadata keypairs to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        """
        # pop immutable keys
        for key in IMMUTABLE_KEYS:
            if key in meta:
                meta.pop(key)

        # set first document with did == _id
        self.col.update_one(
            {
                "_id": "{}:{}".format(scope.internal, name)
            },
            {
                '$set': meta,
                '$setOnInsert': {
                    'scope': "{}".format(scope.external),
                    'vo': "{}".format(scope.vo),
                    'name': "{}".format(name)
                }
            },
            upsert=True
        )

    def delete_metadata(self, scope, name, key, session=None):
        """
        Delete a key from metadata.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        """
        meta = {key: ""}
        try:
            self.col.update_one({"_id": "{}:{}".format(scope.internal, name)}, {'$unset': meta})
        except Exception as e:
            raise exception.DataIdentifierNotFound(e)

    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, session=None):
        if not ignore_dids:
            ignore_dids = set()

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # instantiate fe and create mongo query
        fe = FilterEngine(filters, model_class=None, strict_coerce=False)
        mongo_query_str = fe.create_mongo_query(
            additional_filters=[
                ('scope', operator.eq, scope.internal),
                ('vo', operator.eq, scope.vo)
            ]
        )

        if recursive:
            # TODO: possible, but requires retrieving the results of a concurrent sqla query to call list_content on for datasets and containers
            raise exception.UnsupportedOperation("'{}' metadata module does not currently support recursive searches".format(
                self.plugin_name.lower()
            ))

        if long:
            query_result = self.col.find(mongo_query_str)
            if limit:
                query_result = query_result.limit(limit)
            for did in query_result:
                did_full = did_full = "{}:{}".format(did['scope'], did['name'])
                if did_full not in ignore_dids:         # aggregating recursive queries may contain duplicate DIDs
                    ignore_dids.add(did_full)
                    yield {
                        'scope': InternalScope(did['scope']),
                        'name': did['name'],
                        'did_type': "N/A",
                        'bytes': "N/A",
                        'length': "N/A"
                    }
        else:
            query_result = self.col.find(mongo_query_str)
            if limit:
                query_result = query_result.limit(limit)
            for did in query_result:
                did_full = did_full = "{}:{}".format(did['scope'], did['name'])
                if did_full not in ignore_dids:         # aggregating recursive queries may contain duplicate DIDs
                    ignore_dids.add(did_full)
                    yield did['name']

    def manages_key(self, key, session=None):
        return True

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name
