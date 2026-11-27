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

import json as json_lib
import operator
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import and_, select
from sqlalchemy.exc import DataError, NoResultFound

from rucio.common import exception
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session, stream_session, transactional_session
from rucio.db.sqla.util import json_implemented

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


class JSONDidMeta(DidMetaPlugin):
    """
    A plugin to store DID metadata on a table on the relational database, using JSON blobs
    """

    def __init__(self):
        super(JSONDidMeta, self).__init__()

        self._plugin_name = "JSON"

    @read_session
    def get_metadata(self, scope, name, *, session: "Session"):
        """
        Get data identifier metadata (JSON)

        :param scope: The scope name.
        :param name: The data identifier name.
        :param session: The database session in use.
        """
        if not json_implemented(session=session):
            raise NotImplementedError

        try:
            stmt = select(
                models.DidMeta
            ).where(
                and_(models.DidMeta.scope == scope,
                     models.DidMeta.name == name)
            )
            row = session.execute(stmt).scalar_one()
            meta = getattr(row, 'meta')
            return json_lib.loads(meta) if session.bind.dialect.name in ['oracle', 'sqlite'] else meta
        except NoResultFound:
            return {}

    @transactional_session
    def set_metadata(self, scope, name, key, value, recursive=False, *, session: "Session"):
        self.set_metadata_bulk(scope=scope, name=name, metadata={key: value}, recursive=recursive, session=session)

    @transactional_session
    def set_metadata_bulk(self, scope, name, metadata, recursive=False, *, session: "Session"):
        if not json_implemented(session=session):
            raise NotImplementedError

        stmt = select(
            models.DataIdentifier
        ).where(
            and_(models.DataIdentifier.scope == scope,
                 models.DataIdentifier.name == name)
        )
        if session.execute(stmt).one_or_none() is None:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (scope, name))

        stmt = select(
            models.DidMeta
        ).where(
            and_(models.DidMeta.scope == scope,
                 models.DidMeta.name == name)
        )
        row_did_meta = session.execute(stmt).scalar_one_or_none()
        if row_did_meta is None:
            # Add metadata column to new table (if not already present)
            row_did_meta = models.DidMeta(scope=scope, name=name)
            row_did_meta.save(session=session, flush=False)

        existing_meta = {}
        if hasattr(row_did_meta, 'meta'):
            if row_did_meta.meta:
                if session.bind.dialect.name in ['oracle', 'sqlite']:
                    # Oracle and sqlite returns a string instead of a dict
                    existing_meta = json_lib.loads(cast("str", row_did_meta.meta))
                else:
                    existing_meta = cast("dict[str, Any]", row_did_meta.meta)

        for key, value in metadata.items():
            existing_meta[key] = value

        row_did_meta.meta = None
        session.flush()

        # Oracle insert takes a string as input
        if session.bind.dialect.name in ['oracle', 'sqlite']:
            existing_meta = json_lib.dumps(existing_meta)

        row_did_meta.meta = existing_meta
        row_did_meta.save(session=session, flush=True)

    @transactional_session
    def delete_metadata(self, scope, name, key, *, session: "Session"):
        """
        Delete a key from the metadata column

        :param scope: the scope of DID
        :param name: the name of the DID
        :param key: the key to be deleted
        :param session: The database session in use.
        """
        if not json_implemented(session=session):
            raise NotImplementedError

        try:
            stmt = select(
                models.DidMeta
            ).where(
                and_(models.DidMeta.scope == scope,
                     models.DidMeta.name == name)
            )
            row = session.execute(stmt).scalar_one()
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
            raise exception.DataIdentifierNotFound(f"Key not found for data identifier '{scope}:{name}'")

    @stream_session
    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, *, session: "Session"):
        if not json_implemented(session=session):
            raise NotImplementedError

        if not ignore_dids:
            ignore_dids = set()

        # mapping for semantic <type> to a (set of) recognised DIDType(s).
        type_to_did_type_mapping: dict[str, list[DIDType]] = {
            'all': [DIDType.CONTAINER, DIDType.DATASET, DIDType.FILE],
            'collection': [DIDType.CONTAINER, DIDType.DATASET],
            'container': [DIDType.CONTAINER],
            'dataset': [DIDType.DATASET],
            'file': [DIDType.FILE]
        }
        did_type = did_type.lower()
        if did_type not in type_to_did_type_mapping:
            raise exception.UnsupportedOperation(
                '{} is not a valid type. Valid types are {}'.format(did_type, ', '.join(type_to_did_type_mapping)))

        # backwards compatibility for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # instantiate fe and create sqla query, note that coercion to a model keyword
        # is not appropriate here as the filter words are stored in a single json column.
        fe = FilterEngine(filters, model_class=models.DidMeta, strict_coerce=False)
        stmt = fe.create_sqla_query(
            additional_model_attributes=[
                models.DidMeta.scope,
                models.DidMeta.name
            ], additional_filters=[
                (models.DidMeta.scope, operator.eq, scope)
            ],
            json_column=models.DidMeta.meta,
            session=session
        )
        # The DID type is stored on the DIDs table, so join it to filter on the requested
        # type and to report type and size information in long output.
        stmt = stmt.join(
            models.DataIdentifier,
            and_(models.DataIdentifier.scope == models.DidMeta.scope,
                 models.DataIdentifier.name == models.DidMeta.name)
        ).add_columns(
            models.DataIdentifier.did_type,
            models.DataIdentifier.bytes,
            models.DataIdentifier.length
        ).where(
            models.DataIdentifier.did_type.in_(type_to_did_type_mapping[did_type])
        )

        if limit:
            stmt = stmt.limit(
                limit
            )
        if recursive:
            from rucio.core.did import list_content

            # Get attached DIDs and save in list because query has to be finished before starting a new one in the recursion
            collections_content = []
            for did in session.execute(stmt).yield_per(100):
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
            for did in session.execute(stmt).yield_per(5):                  # don't unpack this as it makes it dependent on query return order!
                if long:
                    did_full = "{}:{}".format(did.scope, did.name)
                    if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                        ignore_dids.add(did_full)
                        yield {
                            'scope': did.scope,
                            'name': did.name,
                            'did_type': did.did_type.name,
                            'bytes': did.bytes,
                            'length': did.length
                        }
                else:
                    did_full = "{}:{}".format(did.scope, did.name)
                    if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                        ignore_dids.add(did_full)
                        yield did.name
        except DataError as e:
            raise exception.InvalidMetadata("Database query failed: {}. This can be raised when the datatype of a key is inconsistent between dids.".format(e))

    @read_session
    def manages_key(self, key, *, session: "Session"):
        return json_implemented(session=session)
