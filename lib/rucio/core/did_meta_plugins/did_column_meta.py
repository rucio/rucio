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

from datetime import datetime, timedelta
import operator

from sqlalchemy import update, inspect
from sqlalchemy.exc import CompileError, InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import true

from rucio.common import exception
from rucio.core import account_counter, rse_counter
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import stream_session, read_session, transactional_session


class DidColumnMeta(DidMetaPlugin):
    """
    A metadata plugin to interact with the base did table metadata.
    """
    def __init__(self):
        super(DidColumnMeta, self).__init__()
        self.plugin_name = "DID_COLUMN"

    @read_session
    def get_metadata(self, scope, name, session=None):
        """
        Get data identifier metadata.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param session: The database session in use.
        """
        try:
            row = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
                with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').one()
            d = {}
            for column in row.__table__.columns:
                d[column.name] = getattr(row, column.name)
            return d
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    def set_metadata(self, scope, name, key, value, recursive=False, session=None):
        self.set_metadata_bulk(scope=scope, name=name, metadata={key: value}, recursive=recursive, session=session)

    @transactional_session
    def set_metadata_bulk(self, scope, name, metadata, recursive=False, session=None):
        did_query = session.query(models.DataIdentifier).with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').filter_by(scope=scope, name=name)
        if did_query.one_or_none() is None:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (scope, name))

        remainder = {}
        for key, value in metadata.items():
            if key == 'lifetime':
                try:
                    expired_at = None
                    if value is not None:
                        expired_at = datetime.utcnow() + timedelta(seconds=float(value))
                    rowcount = did_query.update({'expired_at': expired_at}, synchronize_session='fetch')
                except TypeError as error:
                    raise exception.InvalidValueForKey(error)
                if not rowcount:
                    # check for did presence
                    raise exception.UnsupportedOperation('%s for %s:%s cannot be updated' % (key, scope, name))
            elif key in ['guid', 'events']:
                rowcount = did_query.filter_by(did_type=DIDType.FILE).update({key: value}, synchronize_session=False)
                if not rowcount:
                    # check for did presence
                    raise exception.UnsupportedOperation('%s for %s:%s cannot be updated' % (key, scope, name))

                session.query(models.DataIdentifierAssociation).filter_by(child_scope=scope, child_name=name, child_type=DIDType.FILE).update({key: value}, synchronize_session=False)
                if key == 'events':
                    for parent_scope, parent_name in session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name).filter_by(child_scope=scope, child_name=name):
                        events = session.query(func.sum(models.DataIdentifierAssociation.events)).filter_by(scope=parent_scope, name=parent_name).one()[0]
                        session.query(models.DataIdentifier).filter_by(scope=parent_scope, name=parent_name).update({'events': events}, synchronize_session=False)
            elif key == 'adler32':
                rowcount = did_query.filter_by(did_type=DIDType.FILE).update({key: value}, synchronize_session=False)
                if not rowcount:
                    # check for did presence
                    raise exception.UnsupportedOperation('%s for %s:%s cannot be updated' % (key, scope, name))

                session.query(models.DataIdentifierAssociation).filter_by(child_scope=scope, child_name=name, child_type=DIDType.FILE).update({key: value}, synchronize_session=False)
                session.query(models.Request).filter_by(scope=scope, name=name).update({key: value}, synchronize_session=False)
                session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name).update({key: value}, synchronize_session=False)
            elif key == 'bytes':
                rowcount = did_query.filter_by(did_type=DIDType.FILE).update({key: value}, synchronize_session=False)
                if not rowcount:
                    # check for did presence
                    raise exception.UnsupportedOperation('%s for %s:%s cannot be updated' % (key, scope, name))

                session.query(models.DataIdentifierAssociation).filter_by(child_scope=scope, child_name=name, child_type=DIDType.FILE).update({key: value}, synchronize_session=False)
                session.query(models.Request).filter_by(scope=scope, name=name).update({key: value}, synchronize_session=False)

                for account, bytes_, rse_id, rule_id in session.query(models.ReplicaLock.account, models.ReplicaLock.bytes, models.ReplicaLock.rse_id, models.ReplicaLock.rule_id).filter_by(scope=scope, name=name):
                    session.query(models.ReplicaLock).filter_by(scope=scope, name=name, rule_id=rule_id, rse_id=rse_id).update({key: value}, synchronize_session=False)
                    account_counter.decrease(rse_id=rse_id, account=account, files=1, bytes_=bytes_, session=session)
                    account_counter.increase(rse_id=rse_id, account=account, files=1, bytes_=value, session=session)

                for bytes_, rse_id in session.query(models.RSEFileAssociation.bytes, models.RSEFileAssociation.rse_id).filter_by(scope=scope, name=name):
                    session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name, rse_id=rse_id).update({key: value}, synchronize_session=False)
                    rse_counter.decrease(rse_id=rse_id, files=1, bytes_=bytes_, session=session)
                    rse_counter.increase(rse_id=rse_id, files=1, bytes_=value, session=session)

                for parent_scope, parent_name in session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name).filter_by(child_scope=scope, child_name=name):
                    values = {}
                    values['length'], values['bytes'], values['events'] = session.query(func.count(models.DataIdentifierAssociation.scope),
                                                                                        func.sum(models.DataIdentifierAssociation.bytes),
                                                                                        func.sum(models.DataIdentifierAssociation.events)).filter_by(scope=parent_scope, name=parent_name).one()
                    session.query(models.DataIdentifier).filter_by(scope=parent_scope, name=parent_name).update(values, synchronize_session=False)
                    session.query(models.DatasetLock).filter_by(scope=parent_scope, name=parent_name).update({'length': values['length'], 'bytes': values['bytes']}, synchronize_session=False)
            else:
                remainder[key] = value

        if remainder:
            try:
                rowcount = did_query.update(remainder, synchronize_session='fetch')
            except CompileError as error:
                raise exception.InvalidMetadata(error)
            except InvalidRequestError:
                raise exception.InvalidMetadata("Some of the keys are not accepted: " + str(list(remainder.keys())))
            if not rowcount:
                raise exception.UnsupportedOperation('Some of the keys for %s:%s cannot be updated: %s' % (scope, name, str(list(remainder.keys()))))

            # propagate metadata updates to child content
            if recursive:
                content_query = session.query(models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.child_name)
                content_query = content_query.with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').filter_by(scope=scope, name=name)

                for child_scope, child_name in content_query:
                    try:
                        stmt = update(models.DataIdentifier)\
                            .prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')\
                            .filter_by(scope=child_scope, name=child_name)\
                            .execution_options(synchronize_session='fetch')\
                            .values(remainder)
                        session.execute(stmt)
                    except CompileError as error:
                        raise exception.InvalidMetadata(error)
                    except InvalidRequestError:
                        raise exception.InvalidMetadata("Some of the keys are not accepted recursively: " + str(list(remainder.keys())))

    @stream_session
    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, session=None):
        """
        Search data identifiers.

        :param scope: the scope name.
        :param filters: dictionary of attributes by which the results should be filtered.
        :param did_type: the type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
        :param ignore_case: ignore case distinctions.
        :param limit: limit number.
        :param offset: offset number.
        :param long: Long format option to display more information for each DID.
        :param session: The database session in use.
        :param recursive: Recursively list DIDs content.
        :param ignore_dids: List of DIDs to refrain from yielding.
        """
        if not ignore_dids:
            ignore_dids = set()

        # mapping for semantic <type> to a (set of) recognised DIDType(s).
        type_to_did_type_mapping = {
            'all': [DIDType.CONTAINER, DIDType.DATASET, DIDType.FILE],
            'collection': [DIDType.CONTAINER, DIDType.DATASET],
            'container': [DIDType.CONTAINER],
            'dataset': [DIDType.DATASET],
            'file': [DIDType.FILE]
        }

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # for each or_group, make sure there is a mapped "did_type" filter.
        # if type maps to many DIDTypes, the corresponding or_group will be copied the required number of times to satisfy all the logical possibilities.
        filters_tmp = []
        for or_group in filters:
            if 'type' not in or_group:
                or_group_type = did_type.lower()
            else:
                or_group_type = or_group.pop('type').lower()
            if or_group_type not in type_to_did_type_mapping.keys():
                raise exception.UnsupportedOperation('{} is not a valid type. Valid types are {}'.format(or_group_type, type_to_did_type_mapping.keys()))

            for mapped_did_type in type_to_did_type_mapping[or_group_type]:
                or_group['did_type'] = mapped_did_type
                filters_tmp.append(or_group.copy())
        filters = filters_tmp

        # instantiate fe and create sqla query
        fe = FilterEngine(filters, model_class=models.DataIdentifier)
        query = fe.create_sqla_query(
            additional_model_attributes=[
                models.DataIdentifier.scope,
                models.DataIdentifier.name,
                models.DataIdentifier.did_type,
                models.DataIdentifier.bytes,
                models.DataIdentifier.length
            ], additional_filters=[
                (models.DataIdentifier.scope, operator.eq, scope),
                (models.DataIdentifier.suppressed, operator.ne, true())
            ],
            session=session
        )
        query.with_hint(models.DataIdentifier, 'NO_EXPAND', 'oracle')

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

        for did in query.yield_per(5):                  # don't unpack this as it makes it dependent on query return order!
            if long:
                did_full = "{}:{}".format(did.scope, did.name)
                if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                    ignore_dids.add(did_full)
                    yield {
                        'scope': did.scope,
                        'name': did.name,
                        'did_type': str(did.did_type),
                        'bytes': did.bytes,
                        'length': did.length
                    }
            else:
                did_full = "{}:{}".format(did.scope, did.name)
                if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                    ignore_dids.add(did_full)
                    yield did.name

    def delete_metadata(self, scope, name, key, session=None):
        """
        Deletes the metadata stored for the given key.

        :param scope: The scope of the did.
        :param name: The name of the did.
        :param key: Key of the metadata.
        """
        raise NotImplementedError('The DidColumnMeta plugin does not currently support deleting metadata.')

    def manages_key(self, key, session=None):
        # Build list of which keys are managed by this plugin.
        #
        all_did_table_columns = []
        for column in inspect(models.DataIdentifier).attrs:
            all_did_table_columns.append(column.key)

        exclude_did_table_columns = [
            'account',
            'availability',
            'complete',
            'created_at',
            'did_type',
            'is_open',
            'monotonic',
            'obsolete',
            'scope',
            'suppressed',
            'updated_at'
        ]

        additional_keys = [
            'lifetime',
            'created_before',
            'created_after',
            'length.gt',
            'length.lt',
            'length.gte',
            'length.lte',
            'type'
        ]

        hardcoded_keys = list(set(all_did_table_columns) - set(exclude_did_table_columns)) + additional_keys

        return key in hardcoded_keys

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.
        :returns: The name of the plugin.
        """
        return self.plugin_name
