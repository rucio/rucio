# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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

from datetime import datetime, timedelta
from six import string_types

from sqlalchemy import or_
from sqlalchemy.exc import CompileError, InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import true

from rucio.common import exception
from rucio.common.utils import str_to_date
from rucio.core import account_counter, rse_counter
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import transactional_session, stream_session, read_session

from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin

HARDCODED_KEYS = [
    "lifetime",
    "guid",
    "events",
    "adler32",
    "bytes",
    "events",

    # Fields on the did table
    "length",
    "md5",
    # "expired_at",
    # "purge_replicas",
    "deleted_at",
    "project",
    "datatype",
    "run_number",
    "stream_name",
    "prod_step",
    "version",
    "campaign",
    "task_id",
    "panda_id",
    "lumiblocknr",
    "provenance",
    "phys_group",
    "transient",
    "accessed_at",
    "closed_at",
    "eol_at",
    "is_archive",
    "constituent",
    "access_cnt",

    # Keys used while listing dids
    "created_before",
    "created_after",
    "guid",
    "length.gt",
    "length.lt",
    "length.gte",
    "length.lte",
    "length",
    "name"
]


class DidColumnMeta(DidMetaPlugin):
    """
    A plugin that stores DID metadata on the DiD table using hardcoded keys as columns.
    """

    def __init__(self):
        super(DidColumnMeta, self).__init__()
        self.plugin_name = "DID_COLUMN"

    @read_session
    def get_metadata(self, scope, name, session=None):
        """
        Get data identifier metadata

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

    @transactional_session
    def set_metadata(self, scope, name, key, value, recursive=False, session=None):
        """
        Add metadata to data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param key: the key.
        :param value: the value.
        :param did: The data identifier info.
        :param recursive: Option to propagate the metadata change to content.
        :param session: The database session in use.
        """
        try:
            rowcount = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
                with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (scope, name))

        if key == 'lifetime':
            try:
                expired_at = None
                if value is not None:
                    expired_at = datetime.utcnow() + timedelta(seconds=float(value))
                rowcount = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).update({'expired_at': expired_at}, synchronize_session='fetch')
            except TypeError as error:
                raise exception.InvalidValueForKey(error)
        elif key in ['guid', 'events']:
            rowcount = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, did_type=DIDType.FILE).update({key: value}, synchronize_session=False)

            session.query(models.DataIdentifierAssociation).filter_by(child_scope=scope, child_name=name, child_type=DIDType.FILE).update({key: value}, synchronize_session=False)
            if key == 'events':
                for parent_scope, parent_name in session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name).filter_by(child_scope=scope, child_name=name):
                    events = session.query(func.sum(models.DataIdentifierAssociation.events)).filter_by(scope=parent_scope, name=parent_name).one()[0]
                    session.query(models.DataIdentifier).filter_by(scope=parent_scope, name=parent_name).update({'events': events}, synchronize_session=False)

        elif key == 'adler32':
            rowcount = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, did_type=DIDType.FILE).update({key: value}, synchronize_session=False)
            session.query(models.DataIdentifierAssociation).filter_by(child_scope=scope, child_name=name, child_type=DIDType.FILE).update({key: value}, synchronize_session=False)
            session.query(models.Request).filter_by(scope=scope, name=name).update({key: value}, synchronize_session=False)
            session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name).update({key: value}, synchronize_session=False)
        elif key == 'bytes':
            rowcount = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, did_type=DIDType.FILE).update({key: value}, synchronize_session=False)
            session.query(models.DataIdentifierAssociation).filter_by(child_scope=scope, child_name=name, child_type=DIDType.FILE).update({key: value}, synchronize_session=False)
            session.query(models.Request).filter_by(scope=scope, name=name).update({key: value}, synchronize_session=False)

            for account, bytes, rse_id, rule_id in session.query(models.ReplicaLock.account, models.ReplicaLock.bytes, models.ReplicaLock.rse_id, models.ReplicaLock.rule_id).filter_by(scope=scope, name=name):
                session.query(models.ReplicaLock).filter_by(scope=scope, name=name, rule_id=rule_id, rse_id=rse_id).update({key: value}, synchronize_session=False)
                account_counter.decrease(rse_id=rse_id, account=account, files=1, bytes=bytes, session=session)
                account_counter.increase(rse_id=rse_id, account=account, files=1, bytes=value, session=session)

            for bytes, rse_id in session.query(models.RSEFileAssociation.bytes, models.RSEFileAssociation.rse_id).filter_by(scope=scope, name=name):
                session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name, rse_id=rse_id).update({key: value}, synchronize_session=False)
                rse_counter.decrease(rse_id=rse_id, files=1, bytes=bytes, session=session)
                rse_counter.increase(rse_id=rse_id, files=1, bytes=value, session=session)

            for parent_scope, parent_name in session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name).filter_by(child_scope=scope, child_name=name):

                values = {}
                values['length'], values['bytes'], values['events'] = session.query(func.count(models.DataIdentifierAssociation.scope),
                                                                                    func.sum(models.DataIdentifierAssociation.bytes),
                                                                                    func.sum(models.DataIdentifierAssociation.events)).filter_by(scope=parent_scope, name=parent_name).one()
                session.query(models.DataIdentifier).filter_by(scope=parent_scope, name=parent_name).update(values, synchronize_session=False)
                session.query(models.DatasetLock).filter_by(scope=parent_scope, name=parent_name).update({'length': values['length'], 'bytes': values['bytes']}, synchronize_session=False)
        else:
            try:
                rowcount = session.query(models.DataIdentifier).\
                    with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
                    filter_by(scope=scope, name=name).\
                    update({key: value}, synchronize_session='fetch')
            except CompileError as error:
                raise exception.InvalidMetadata(error)
            except InvalidRequestError as error:
                raise exception.InvalidMetadata("Key %s is not accepted" % key)

            # propagate metadata updates to child content
            if recursive:
                content_query = session.query(models.DataIdentifierAssociation.child_scope,
                                              models.DataIdentifierAssociation.child_name).\
                    with_hint(models.DataIdentifierAssociation,
                              "INDEX(CONTENTS CONTENTS_PK)", 'oracle').\
                    filter_by(scope=scope, name=name)

                for child_scope, child_name in content_query:
                    try:
                        session.query(models.DataIdentifier).\
                            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
                            filter_by(scope=child_scope, name=child_name).\
                            update({key: value}, synchronize_session='fetch')
                    except CompileError as error:
                        raise exception.InvalidMetadata(error)
                    except InvalidRequestError as error:
                        raise exception.InvalidMetadata("Key %s is not accepted" % key)

        if not rowcount:
            # check for did presence
            raise exception.UnsupportedOperation('%(key)s for %(scope)s:%(name)s cannot be updated' % locals())

    @stream_session
    def list_dids(self, scope, filters, type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, session=None):
        """
        Search data identifiers

        :param scope: the scope name.
        :param filters: dictionary of attributes by which the results should be filtered.
        :param type: the type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
        :param ignore_case: ignore case distinctions.
        :param limit: limit number.
        :param offset: offset number.
        :param long: Long format option to display more information for each DID.
        :param session: The database session in use.
        :param recursive: Recursively list DIDs content.
        """
        types = ['all', 'collection', 'container', 'dataset', 'file']
        if type not in types:
            raise exception.UnsupportedOperation("Valid type are: %(types)s" % locals())

        query = session.query(models.DataIdentifier.scope,
                              models.DataIdentifier.name,
                              models.DataIdentifier.did_type,
                              models.DataIdentifier.bytes,
                              models.DataIdentifier.length).\
            filter(models.DataIdentifier.scope == scope)

        # Exclude suppressed dids
        query = query.filter(models.DataIdentifier.suppressed != true())

        if type == 'all':
            query = query.filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER,
                                     models.DataIdentifier.did_type == DIDType.DATASET,
                                     models.DataIdentifier.did_type == DIDType.FILE))
        elif type.lower() == 'collection':
            query = query.filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER,
                                     models.DataIdentifier.did_type == DIDType.DATASET))
        elif type.lower() == 'container':
            query = query.filter(models.DataIdentifier.did_type == DIDType.CONTAINER)
        elif type.lower() == 'dataset':
            query = query.filter(models.DataIdentifier.did_type == DIDType.DATASET)
        elif type.lower() == 'file':
            query = query.filter(models.DataIdentifier.did_type == DIDType.FILE)

        for (k, v) in filters.items():

            if k not in ['created_before', 'created_after', 'length.gt', 'length.lt', 'length.lte', 'length.gte', 'length'] \
                    and not hasattr(models.DataIdentifier, k):
                raise exception.KeyNotFound(k)

            if isinstance(v, string_types) and ('*' in v or '%' in v):
                if v in ('*', '%', u'*', u'%'):
                    continue
                if session.bind.dialect.name == 'postgresql':
                    query = query.filter(getattr(models.DataIdentifier, k).
                                        like(v.replace('*', '%').replace('_', '\_'),  # NOQA: W605
                                            escape='\\'))
                else:
                    query = query.filter(getattr(models.DataIdentifier, k).
                                        like(v.replace('*', '%').replace('_', '\_'), escape='\\'))  # NOQA: W605
            elif k == 'created_before':
                created_before = str_to_date(v)
                query = query.filter(models.DataIdentifier.created_at <= created_before)
            elif k == 'created_after':
                created_after = str_to_date(v)
                query = query.filter(models.DataIdentifier.created_at >= created_after)
            elif k == 'guid':
                query = query.filter_by(guid=v).\
                    with_hint(models.ReplicaLock, "INDEX(DIDS_GUIDS_IDX)", 'oracle')
            elif k == 'length.gt':
                query = query.filter(models.DataIdentifier.length > v)
            elif k == 'length.lt':
                query = query.filter(models.DataIdentifier.length < v)
            elif k == 'length.gte':
                query = query.filter(models.DataIdentifier.length >= v)
            elif k == 'length.lte':
                query = query.filter(models.DataIdentifier.length <= v)
            elif k == 'length':
                query = query.filter(models.DataIdentifier.length == v)
            else:
                query = query.filter(getattr(models.DataIdentifier, k) == v)

        if 'name' in filters:
            if '*' in filters['name']:
                query = query.\
                    with_hint(models.DataIdentifier, "NO_INDEX(dids(SCOPE,NAME))", 'oracle')
            else:
                query = query.\
                    with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle')

        if limit:
            query = query.limit(limit)

        if recursive:
            # Get attachted DIDs and save in list because query has to be finished before starting a new one in the recursion
            collections_content = []
            parent_scope = scope

            from rucio.core.did import list_content

            for scope, name, did_type, bytes, length in query.yield_per(100):
                if (did_type == DIDType.CONTAINER or did_type == DIDType.DATASET):
                    collections_content += [did for did in list_content(scope=scope, name=name)]

            # List DIDs again to use filter
            for did in collections_content:
                filters['name'] = did['name']
                for result in self.list_dids(scope=did['scope'], filters=filters, recursive=True, type=type, limit=limit, offset=offset, long=long, session=session):
                    yield result

        if long:
            for scope, name, did_type, bytes, length in query.yield_per(5):
                yield {'scope': scope,
                       'name': name,
                       'did_type': str(did_type),
                       'bytes': bytes,
                       'length': length}
        else:
            for scope, name, did_type, bytes, length in query.yield_per(5):
                yield name

    def delete_metadata(self, scope, name, key, session=None):
        """
        Deletes the metadata stored for the given key.

        :param scope: The scope of the did.
        :param name: The name of the did.
        :param key: Key of the metadata.
        """
        raise NotImplementedError('The DidColumnMeta plugin does not currently support deleting metadata.')

    def manages_key(self, key):
        """
        Returns wether key is managed by this plugin or not.

        :param key: Key of the metadata.
        :returns (Boolean)
        """
        if key in HARDCODED_KEYS:  # or hasattr(models.DataIdentifier, key):
            return True

        return False

    def get_plugin_name(self):
        """
        Returns a unique identifier for the Plugin.
        This can be later used for filtering down results to this plugin only."
        :returns: (STRING) The name of the plugin
        """
        return self.plugin_name
