# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# Authors:
# - Rob Barnsley <rob.barnsley@skao.int>, 2021

import json as json_lib
import operator
from six import print_

import pymongo
from sqlalchemy.exc import DataError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import config
from rucio.common import exception
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.db.sqla.util import json_implemented

class MongoDidMeta(DidMetaPlugin):
    def __init__(self):
        super(MongoDidMeta, self).__init__()
        self.mongo_service_ip = config.config_get('metadata', 'mongo_service_ip')
        self.mongo_service_port = config.config_get('metadata', 'mongo_service_port')
        self.mongo_db_name = config.config_get('metadata', 'mongo_db_name')
        self.mongo_collection_name = config.config_get('metadata', 'mongo_collection_name')

        self.plugin_name = "MONGO"

    def get_metadata(self, scope, name, session=None):
        """
        Get data identifier metadata.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param session: The database session in use.
        """
        try:
            client = pymongo.MongoClient("mongodb://{}:{}/".format(self.mongo_service_ip, self.mongo_service_port))
            db = client[self.mongo_db_name]
            col = db[self.mongo_collection_name]
            try:
                doc = col.find_one({"_id" : "{}:{}".format(scope, name)})
            except Exception as e:
                raise exception.DataIdentifierNotFound(e)
            if not doc:
                raise NoResultFound
            doc.pop('_id')
            return doc
        except NoResultFound:
            raise exception.DataIdentifierNotFound("No metadata found for did '%(scope)s:%(name)s'" % locals())

    def set_metadata(self, scope, name, key, value, recursive=False, session=None):
        self.set_metadata_bulk(scope=scope, name=name, meta={key: value}, recursive=recursive, session=session)

    def set_metadata_bulk(self, scope, name, meta, recursive=False, session=None):
        try:
            client = pymongo.MongoClient("mongodb://{}:{}/".format(self.mongo_service_ip, self.mongo_service_port))
            db = client[self.mongo_db_name]
            col = db[self.mongo_collection_name]
            col.update_one({"_id" : "{}:{}".format(scope, name)}, {'$set': meta}, upsert=True)
        except Exception as e:
            raise exception.DataIdentifierNotFound(e)

    def delete_metadata(self, scope, name, key, session=None):
        """
        Delete a key from the metadata column

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        """
        meta = {key: ""}
        try:
            client = pymongo.MongoClient("mongodb://{}:{}/".format(self.mongo_service_ip, self.mongo_service_port))
            db = client[self.mongo_db_name]
            col = db[self.mongo_collection_name]
            col.update_one({"_id" : "{}:{}".format(scope, name)}, {'$unset': meta})
        except Exception as e:
            raise exception.DataIdentifierNotFound(e)

    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, session=None):
        
        if not ignore_dids:
            ignore_dids = set()

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]
        
        # instantiate fe
        fe = FilterEngine(filters, model_class=None, strict_coerce=False)

        #TODO: next block should be put inside the filter engine class ultimately, e.g. create_mongo_query()
        raise exception.DataIdentifierNotFound(fe.filters)                #FIXME

    @read_session
    def manages_key(self, key, session=None):
        return True

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.
        :returns: The name of the plugin.
        """
        return self.plugin_name
