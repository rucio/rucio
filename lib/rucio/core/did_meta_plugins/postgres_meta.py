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

import json
import operator

import psycopg2
import psycopg2.extras

from rucio.common import config
from rucio.common import exception
from rucio.common.types import InternalScope
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine


class ExternalPostgresDidMeta(DidMetaPlugin):
    # TODO: column-based plugin? mixed-mode (json & columns)?
    pass


class ExternalPostgresJSONDidMeta(DidMetaPlugin):
    def __init__(self, host=None, port=None, db=None, user=None, password=None, db_schema=None, table=None,
                 table_is_managed=None, table_column_vo=None, table_column_scope=None, table_column_name=None,
                 table_column_data=None):
        super(ExternalPostgresJSONDidMeta, self).__init__()
        if host is None:
            host = config.config_get('metadata', 'postgres_service_host')
        if port is None:
            port = config.config_get('metadata', 'postgres_service_port')
        if db is None:
            db = config.config_get('metadata', 'postgres_db')
        if user is None:
            user = config.config_get('metadata', 'postgres_user')
        if password is None:
            password = config.config_get('metadata', 'postgres_password')
        if db_schema is None:
            db_schema = config.config_get('metadata', 'postgres_db_schema', default='public')
        if table is None:
            table = config.config_get('metadata', 'postgres_table', default='dids')
        if table_is_managed is None:
            table_is_managed = config.config_get_bool('metadata', 'postgres_table_is_managed', default=False)
        if table_column_vo is None:
            table_column_vo = config.config_get('metadata', 'postgres_table_column_vo', default='vo')
        if table_column_scope is None:
            table_column_scope = config.config_get('metadata', 'postgres_table_column_scope', default='scope')
        if table_column_name is None:
            table_column_name = config.config_get('metadata', 'postgres_table_column_name', default='name')
        if table_column_data is None:
            table_column_data = config.config_get('metadata', 'postgres_table_column_data', default='data')

        self.fixed_table_columns = {
            'vo': table_column_vo,
            'scope': table_column_scope,
            'name': table_column_name
        }
        self.jsonb_column = table_column_data

        self.table = table
        self.client = psycopg2.connect(
            host=host,
            port=port,
            database=db,
            user=user,
            password=password)

        # set search_path to include database schema by default
        cur = self.client.cursor()
        statement = "SET search_path TO {};".format(db_schema)
        cur.execute(statement)
        cur.close()

        if not table_is_managed:                    # not managed by Rucio, so just verify table schema
            self._verify_table_schema(table_column_vo, table_column_scope, table_column_name, table_column_data)
        else:                                       # managed by Rucio, create a metadata table if it doesn't exist
            self._try_create_metadata_table()

        self.plugin_name = "POSTGRES_JSON"

    def _try_create_metadata_table(self):
        """
        Try to create a metadata table.
        """
        table_clauses = (
            ("id", "bigint", "NOT NULL", "GENERATED ALWAYS AS IDENTITY"),
            ("vo", "varchar", "NOT NULL"),
            ("scope", "varchar", "NOT NULL"),
            ("name", "varchar", "NOT NULL"),
            ("data", "jsonb", "DEFAULT", "'{}'::jsonb"),
            ("UNIQUE", "(scope, name)")  # unique scope+name table constraint, required for ON CONFLICT
        )
        statement = "CREATE TABLE IF NOT EXISTS {} ({})".format(
            self.table,
            ', '.join([' '.join(clause) for clause in table_clauses]))

        cur = self.client.cursor()
        cur.execute(statement)
        cur.close()
        self.client.commit()

    def _verify_table_schema(self, table_column_vo, table_column_scope, table_column_name, table_column_data):
        """
        Rudimentary verification that the metadata table schema meets the requirements for the plugin.

        Should be called when using externally managed database tables as a sanity check.

        :param table_column_vo: The table column used for the vo
        :param table_column_scope: The table column used for the scope
        :param table_column_name: The table column used for the name
        :param table_column_data: The table column used for the data
        :raises: MetadataSchemaMismatchError
        """
        # Check mandatory columns are of right data type and have the right nullable qualifier.
        statement = "SELECT column_name, data_type, is_nullable " \
                    "FROM INFORMATION_SCHEMA.COLUMNS where table_name = '{}';".format(self.table)
        cur = self.client.cursor()
        cur.execute(statement)
        existing_table_columns = cur.fetchall()
        cur.close()

        mandatory_column_specifications = [
            (table_column_vo, "character varying", "NO"),
            (table_column_scope, "character varying", "NO"),
            (table_column_name, "character varying", "NO"),
            (table_column_data, "jsonb", "YES")
        ]
        for specification in mandatory_column_specifications:
            if specification not in existing_table_columns:
                raise exception.MetadataSchemaMismatchError(
                    "mandatory table column {} does not match that defined in the required table schema {}".format(
                        specification, existing_table_columns))

        # Check required table constraints exist.
        statement = "SELECT con.contype AS constraint_type, " \
                    "(SELECT array_agg(att.attname) FROM pg_attribute att " \
                    " INNER JOIN unnest(con.conkey) unnest(conkey) ON unnest.conkey = att.attnum " \
                    " WHERE att.attrelid = con.conrelid) AS columns " \
                    "FROM pg_constraint con " \
                    "INNER JOIN pg_class rel ON rel.oid = con.conrelid " \
                    "INNER JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace " \
                    "WHERE rel.relname = '{}';".format(self.table)
        cur = self.client.cursor()
        cur.execute(statement)
        existing_table_constraints = cur.fetchall()  # list of (constraint_type, [columns])
        cur.close()

        mandatory_table_constraints = [
            ("u", [table_column_scope, table_column_name]),  # unique scope+name table constraint
        ]
        for constraint in mandatory_table_constraints:
            if constraint not in existing_table_constraints:
                raise exception.MetadataSchemaMismatchError(
                    "mandatory table constraint {} does not match that defined in the required table schema {}".format(
                        constraint, len(existing_table_constraints)))

    def _drop_metadata_table(self):
        statement = "DROP TABLE IF EXISTS {};".format(self.table)
        cur = self.client.cursor()
        cur.execute(statement)
        cur.close()
        self.client.commit()

    def get_metadata(self, scope, name, session=None):
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: the metadata for the did
        """
        statement = "SELECT data from {} ".format(self.table) + \
                    "WHERE scope='{}' AND name='{}';".format(scope.internal, name)
        cur = self.client.cursor()
        cur.execute(statement)
        metadata = cur.fetchone()
        cur.close()

        if not metadata:
            raise exception.DataIdentifierNotFound("No metadata found for did '{}:{}".format(scope, name))

        return metadata[0]

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
        # upsert metadata
        statement = "INSERT INTO {} (scope, name, vo, data) ".format(self.table) + \
                    "VALUES ('{}', '{}', '{}', '{}') ".format(scope.external, name, scope.vo, json.dumps(meta)) + \
                    "ON CONFLICT (scope, name) DO UPDATE set data = {}.data || EXCLUDED.data;".format(self.table)
        cur = self.client.cursor()
        cur.execute(statement)
        cur.close()
        self.client.commit()

    def delete_metadata(self, scope, name, key, session=None):
        """
        Delete a key from metadata.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        :param session: the database session in use
        """
        statement = "UPDATE {} ".format(self.table) + \
                    "SET data = {}.data - '{}';".format(self.table, key)
        cur = self.client.cursor()
        cur.execute(statement)
        cur.close()
        self.client.commit()

    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, session=None):

        if not ignore_dids:
            ignore_dids = set()

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        try:
            # instantiate fe and create postgres query
            fe = FilterEngine(filters, model_class=None, strict_coerce=False)
            postgres_query_str = fe.create_postgres_query(
                additional_filters=[
                    ('scope', operator.eq, scope.internal),
                    ('vo', operator.eq, scope.vo)
                ],
                fixed_table_columns=self.fixed_table_columns,
                jsonb_column=self.jsonb_column
            )
        except Exception as e:
            raise exception.DataIdentifierNotFound(e)

        if recursive:
            # TODO: possible, but requires retrieving the results of a concurrent sqla query to call list_content
            #       on for datasets and containers
            raise exception.UnsupportedOperation(
                "'{}' metadata module does not currently support recursive searches".format(self.plugin_name.lower())
            )

        statement = "SELECT * FROM {} WHERE {} ".format(self.table, postgres_query_str)
        if limit:
            statement += "LIMIT {}".format(limit)
        cur = self.client.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(statement)
        query_result = cur.fetchall()
        cur.close()

        if long:
            for row in query_result:
                did = "{}:{}".format(row['scope'], row['name'])
                if did not in ignore_dids:         # aggregating recursive queries may contain duplicate DIDs
                    ignore_dids.add(did)
                    yield {
                        'scope': InternalScope(row['scope']),
                        'name': row['name'],
                        'did_type': "N/A",
                        'bytes': "N/A",
                        'length': "N/A"
                    }
        else:
            for row in query_result:
                did = "{}:{}".format(row['scope'], row['name'])
                if did not in ignore_dids:         # aggregating recursive queries may contain duplicate DIDs
                    ignore_dids.add(did)
                    yield row['name']

    def manages_key(self, key, session=None):
        return True

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this
        plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name
