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
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2020
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2019
# - Yun-Pin Sun <winter0128@gmail.com>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013-2018
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2014-2015
# - Wen Guan <wguan.icedew@gmail.com>, 2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Tobias Wegner <twegner@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019
# - Brandon White, <bjwhite@fnal.gov>, 2019
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Rizart Dona <rizart.dona@cern.ch>, 2021

import json as json_lib
import operator
from six import print_

from sqlalchemy.exc import DataError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import exception
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.db.sqla.util import json_implemented


class JSONDidMeta(DidMetaPlugin):
    """
    A plugin to store DID metadata on a table on the relational database, using JSON blobs
    """

    def __init__(self):
        super(JSONDidMeta, self).__init__()
        self.plugin_name = "JSON"

    @read_session
    def get_metadata(self, scope, name, session=None):
        """
        Get data identifier metadata (JSON)

        :param scope: The scope name.
        :param name: The data identifier name.
        :param session: The database session in use.
        """
        if not json_implemented(session=session):
            raise NotImplementedError

        try:
            row = session.query(models.DidMeta).filter_by(scope=scope, name=name).one()
            meta = getattr(row, 'meta')
            return json_lib.loads(meta) if session.bind.dialect.name in ['oracle', 'sqlite'] else meta
        except NoResultFound:
            raise exception.DataIdentifierNotFound("No generic metadata found for '%(scope)s:%(name)s'" % locals())

    def set_metadata(self, scope, name, key, value, recursive=False, session=None):
        self.set_metadata_bulk(scope=scope, name=name, meta={key: value}, recursive=recursive, session=session)

    @transactional_session
    def set_metadata_bulk(self, scope, name, meta, recursive=False, session=None):
        if not json_implemented(session=session):
            raise NotImplementedError

        if session.query(models.DataIdentifier).filter_by(scope=scope, name=name).one_or_none() is None:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (scope, name))

        row_did_meta = session.query(models.DidMeta).filter_by(scope=scope, name=name).scalar()
        if row_did_meta is None:
            # Add metadata column to new table (if not already present)
            row_did_meta = models.DidMeta(scope=scope, name=name)
            row_did_meta.save(session=session, flush=False)

        existing_meta = {}
        if hasattr(row_did_meta, 'meta'):
            if row_did_meta.meta:
                existing_meta = row_did_meta.meta

        # Oracle returns a string instead of a dict
        if session.bind.dialect.name in ['oracle', 'sqlite'] and existing_meta:
            existing_meta = json_lib.loads(existing_meta)

        for key, value in meta.items():
            existing_meta[key] = value

        row_did_meta.meta = None
        session.flush()

        # Oracle insert takes a string as input
        if session.bind.dialect.name in ['oracle', 'sqlite']:
            existing_meta = json_lib.dumps(existing_meta)

        row_did_meta.meta = existing_meta
        row_did_meta.save(session=session, flush=True)

    @transactional_session
    def delete_metadata(self, scope, name, key, session=None):
        """
        Delete a key from the metadata column

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        """
        if not json_implemented(session=session):
            raise NotImplementedError

        try:
            row = session.query(models.DidMeta).filter_by(scope=scope, name=name).one()
            existing_meta = getattr(row, 'meta')
            # Oracle returns a string instead of a dict
            if session.bind.dialect.name in ['oracle', 'sqlite'] and existing_meta is not None:
                existing_meta = json_lib.loads(existing_meta)

            if key not in existing_meta:
                raise exception.KeyNotFound(key)

            existing_meta.pop(key, None)

            row.meta = None
            session.flush()

            # Oracle insert takes a string as input
            if session.bind.dialect.name in ['oracle', 'sqlite']:
                existing_meta = json_lib.dumps(existing_meta)

            row.meta = existing_meta
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Key not found for data identifier '%(scope)s:%(name)s'" % locals())

    @stream_session
    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, session=None):
        if not json_implemented(session=session):
            raise NotImplementedError

        if not ignore_dids:
            ignore_dids = set()

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # instantiate fe and create sqla query, note that coercion to a model keyword
        # is not appropriate here as the filter words are stored in a single json column.
        fe = FilterEngine(filters, model_class=models.DidMeta, strict_coerce=False)
        query = fe.create_sqla_query(
            additional_model_attributes=[
                models.DidMeta.scope,
                models.DidMeta.name
            ], additional_filters=[
                (models.DidMeta.scope, operator.eq, scope)
            ],
            json_column = models.DidMeta.meta
        ) 

        #raise exception.DataIdentifierNotFound(FilterEngine.print_query(query))               #FIXME

        if limit:
            query = query.limit(limit)
        if recursive:
            from rucio.core.did import list_content

            # Get attached DIDs and save in list because query has to be finished before starting a new one in the recursion
            collections_content = []
            for did in query.yield_per(100):
                if (did.did_type == DIDType.CONTAINER or did.did_type == DIDType.DATASET):
                    collections_content += [d for d in list_content(scope=did.scope, name=did.name)]

            # Replace any name filtering with recursed DID names.
            for did in collections_content:
                for or_group in filters:
                    or_group['name'] = did['name']
                for result in self.list_dids(scope=did['scope'], filters=filters, recursive=True, did_type=did_type, limit=limit, offset=offset, 
                                            long=long, ignore_dids=ignore_dids, session=session):
                    yield result

        try:
            for did in query.yield_per(5):                  # don't unpack this as it makes it dependent on query return order!
                if long: 
                    did_full = "{}:{}".format(did.scope, did.name)
                    if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                        ignore_dids.add(did_full)
                        yield {
                            'scope': did.scope, 
                            'name': did.name, 
                            'did_type': 'Not available with {} plugin.'.format(self.get_plugin_name()), 
                            'bytes': 'Not available with {} plugin.'.format(self.get_plugin_name()), 
                            'length': 'Not available with {} plugin.'.format(self.get_plugin_name())
                        }
                else:
                    did_full = "{}:{}".format(did.scope, did.name)
                    if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                        ignore_dids.add(did_full)
                        yield did.name
        except DataError as e:
            raise exception.InvalidMetadata("Database query failed. This is usually raised when there is an incompatible datatype in a filter expression.")

    @read_session
    def manages_key(self, key, session=None):
        return json_implemented(session=session)

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.
        :returns: The name of the plugin.
        """
        return self.plugin_name
