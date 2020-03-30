# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2019 - 2020
#
# PY3K COMPATIBLE
import json as json_lib
from six import iteritems

from sqlalchemy import String, cast, type_coerce, JSON
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import text

from rucio.common import exception
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session, stream_session

from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin


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
        if not self.json_implemented(session):
            raise NotImplementedError

        try:
            row = session.query(models.DidMeta).filter_by(scope=scope, name=name).one()
            meta = getattr(row, 'meta')
            return json_lib.loads(meta) if session.bind.dialect.name in ['oracle', 'sqlite'] else meta
        except NoResultFound:
            raise exception.DataIdentifierNotFound("No generic metadata found for '%(scope)s:%(name)s'" % locals())

    @transactional_session
    def set_metadata(self, scope, name, key, value, recursive, session=None):
        """
        Add or update the given metadata to the given did

        :param scope: the scope of the did
        :param name: the name of the did
        :param meta: the metadata to be added or updated
        """
        if not self.json_implemented(session):
            raise NotImplementedError

        try:
            row_did = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).one()
            row_did_meta = session.query(models.DidMeta).filter_by(scope=scope, name=name).scalar()
            if row_did_meta is None:
                # Add metadata column to new table (if not already present)
                row_did_meta = models.DidMeta(scope=scope, name=name)
                row_did_meta.save(session=session, flush=False)
            existing_meta = getattr(row_did_meta, 'meta')
            # Oracle returns a string instead of a dict
            if session.bind.dialect.name in ['oracle', 'sqlite'] and existing_meta is not None:
                existing_meta = json_lib.loads(existing_meta)

            if existing_meta is None:
                existing_meta = {}

            # for k, v in iteritems(meta):
            #     existing_meta[k] = v

            existing_meta[key] = value

            row_did_meta.meta = None
            session.flush()

            # Oracle insert takes a string as input
            if session.bind.dialect.name in ['oracle', 'sqlite']:
                existing_meta = json_lib.dumps(existing_meta)

            row_did_meta.meta = existing_meta
            row_did_meta.save(session=session, flush=True)
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    @transactional_session
    def delete_metadata(self, scope, name, key, session=None):
        """
        Delete a key from the metadata column

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        """
        if not self.json_implemented(session):
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
    def list_dids(self, scope, filters, type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, session=None):
        # Currently for sqlite only add, get and delete is implemented.
        if not self.json_implemented(session):
            raise NotImplementedError

        query = session.query(models.DidMeta)
        if scope is not None:
            query = query.filter(models.DidMeta.scope == scope)
        filters.pop('name', None)
        for k, v in iteritems(filters):
            if session.bind.dialect.name == 'oracle':
                query = query.filter(text("json_exists(meta,'$.%s?(@==''%s'')')" % (k, v)))
            else:
                query = query.filter(cast(models.DidMeta.meta[k], String) == type_coerce(v, JSON))

        if long:
            for row in query.yield_per(5):
                yield {
                    'scope': row.scope,
                    'name': row.name,
                    'did_type': 'Info not available in JSON Plugin',
                    'bytes': 'Info not available in JSON Plugin',
                    'length': 'Info not available in JSON Plugin'
                }
        else:
            for row in query.yield_per(5):
                yield row.name

    def manages_key(self, key):
        """
        Returns whether key is managed by this plugin or not.
        JSON plugin should be considered a wildcard.
        :param key: Key of the metadata.
        :returns (Boolean)
        """
        return True

    def get_plugin_name(self):
        """
        Returns Plugins Name.
        This can then be used when listing the metadata of did to only provide dids from this plugin.
        """
        return self.plugin_name

    def json_implemented(self, session=None):
        """
        Checks if the database on the current server installation can support json fields.
        Check if did meta json table exists.

        :param session: (Optional) The active session of the database.

        :returns: True, if json is supported, False otherwise.
        """
        # if session is None:
        #     session = se.get_session()
        if session.bind.dialect.name == 'oracle':
            oracle_version = int(session.connection().connection.version.split('.')[0])
            if oracle_version < 12:
                return False
        if session.bind.dialect.name == 'sqlite':
            return False
        return True
