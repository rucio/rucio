# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2020
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2020
# - Yun-Pin Sun <winter0128@gmail.com>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013-2021
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2014-2015
# - Wen Guan <wen.guan@cern.ch>, 2015
# - asket <asket.agarwal96@gmail.com>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Tobias Wegner <twegner@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2020
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Vivek Nigam <viveknigam.nigam3@gmail.com>, 2020

import logging
import random
from datetime import datetime, timedelta
from enum import Enum
from hashlib import md5
from re import match

from six import string_types
from sqlalchemy import and_, or_, exists
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import not_, func
from sqlalchemy.sql.expression import bindparam, case, select, true, false

import rucio.core.replica  # import add_replicas
import rucio.core.rule
from rucio.common import exception
from rucio.common.utils import str_to_date, is_archive, chunks
from rucio.core import did_meta_plugins, config as config_core
from rucio.core.message import add_message
from rucio.core.monitor import record_timer_block, record_counter
from rucio.core.naming_convention import validate_name
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import DIDType, DIDReEvaluation, DIDAvailability, RuleState
from rucio.db.sqla.session import read_session, transactional_session, stream_session


@read_session
def list_expired_dids(worker_number=None, total_workers=None, limit=None, session=None):
    """
    List expired data identifiers.

    :param limit: limit number.
    :param session: The database session in use.
    """

    stmt = exists().where(and_(models.ReplicationRule.scope == models.DataIdentifier.scope,
                               models.ReplicationRule.name == models.DataIdentifier.name,
                               models.ReplicationRule.locked == true()))
    query = session.query(models.DataIdentifier.scope, models.DataIdentifier.name,
                          models.DataIdentifier.did_type,
                          models.DataIdentifier.created_at,
                          models.DataIdentifier.purge_replicas).\
        filter(models.DataIdentifier.expired_at < datetime.utcnow(), not_(stmt)).\
        order_by(models.DataIdentifier.expired_at).\
        with_hint(models.DataIdentifier, "index(DIDS DIDS_EXPIRED_AT_IDX)", 'oracle')

    if session.bind.dialect.name in ['oracle', 'mysql', 'postgresql']:
        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='name')
    elif session.bind.dialect.name == 'sqlite' and worker_number and total_workers and total_workers > 0:
        row_count = 0
        dids = list()
        for scope, name, did_type, created_at, purge_replicas in query.yield_per(10):
            if int(md5(name).hexdigest(), 16) % total_workers == worker_number:
                dids.append({'scope': scope,
                             'name': name,
                             'did_type': did_type,
                             'created_at': created_at,
                             'purge_replicas': purge_replicas})
                row_count += 1
            if limit and row_count >= limit:
                return dids
        return dids
    else:
        if worker_number and total_workers:
            raise exception.DatabaseException('The database type %s returned by SQLAlchemy is invalid.' % session.bind.dialect.name)

    if limit:
        query = query.limit(limit)

    return [{'scope': scope, 'name': name, 'did_type': did_type, 'created_at': created_at,
             'purge_replicas': purge_replicas} for scope, name, did_type, created_at, purge_replicas in query]


@transactional_session
def add_did(scope, name, type, account, statuses=None, meta=None, rules=None,
            lifetime=None, dids=None, rse_id=None, session=None):
    """
    Add data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param type: The data identifier type.
    :param account: The account owner.
    :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
    :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
    :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param lifetime: DID's lifetime (in seconds).
    :param dids: The content.
    :param rse_id: The RSE id when registering replicas.
    :param session: The database session in use.
    """
    return add_dids(dids=[{'scope': scope, 'name': name, 'type': type,
                           'statuses': statuses or {}, 'meta': meta or {},
                           'rules': rules, 'lifetime': lifetime,
                           'dids': dids, 'rse_id': rse_id}],
                    account=account, session=session)


@transactional_session
def add_dids(dids, account, session=None):
    """
    Bulk add data identifiers.

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    try:

        for did in dids:
            try:

                if isinstance(did['type'], string_types):
                    did['type'] = DIDType[did['type']]

                if did['type'] == DIDType.FILE:
                    raise exception.UnsupportedOperation("Only collection (dataset/container) can be registered." % locals())

                # Lifetime
                expired_at = None
                if did.get('lifetime'):
                    expired_at = datetime.utcnow() + timedelta(seconds=did['lifetime'])

                # Insert new data identifier
                new_did = models.DataIdentifier(scope=did['scope'], name=did['name'], account=did.get('account') or account,
                                                did_type=did['type'], monotonic=did.get('statuses', {}).get('monotonic', False),
                                                is_open=True, expired_at=expired_at)

                new_did.save(session=session, flush=False)

                if 'meta' in did and did['meta']:
                    # Add metadata
                    set_metadata_bulk(scope=did['scope'], name=did['name'], meta=did['meta'], recursive=False, session=session)

                if did.get('dids', None):
                    attach_dids(scope=did['scope'], name=did['name'], dids=did['dids'],
                                account=account, rse_id=did.get('rse_id'), session=session)

                if did.get('rules', None):
                    rucio.core.rule.add_rules(dids=[did, ], rules=did['rules'], session=session)

                event_type = None
                if did['type'] == DIDType.CONTAINER:
                    event_type = 'CREATE_CNT'
                if did['type'] == DIDType.DATASET:
                    event_type = 'CREATE_DTS'
                if event_type:
                    message = {'account': account.external,
                               'scope': did['scope'].external,
                               'name': did['name'],
                               'expired_at': str(expired_at) if expired_at is not None else None}
                    if account.vo != 'def':
                        message['vo'] = account.vo

                    add_message(event_type, message, session=session)

            except KeyError:
                # ToDo
                raise

        session.flush()

    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-00001: unique constraint.*DIDS_PK.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*UNIQUE constraint failed: dids.scope, dids.name.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.*columns? .*not unique.*', error.args[0]):
            raise exception.DataIdentifierAlreadyExists('Data Identifier already exists!')

        if match('.*IntegrityError.*02291.*integrity constraint.*DIDS_SCOPE_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*FOREIGN KEY constraint failed.*', error.args[0]) \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', error.args[0]) \
                or match('.*IntegrityError.*02291.*integrity constraint.*DIDS_SCOPE_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint.*', error.args[0]) \
                or match('.*ForeignKeyViolation.*insert or update on table.*violates foreign key constraint.*', error.args[0]) \
                or match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]):
            raise exception.ScopeNotFound('Scope not found!')

        raise exception.RucioException(error.args)
    except DatabaseError as error:
        if match('.*(DatabaseError).*ORA-14400.*inserted partition key does not map to any partition.*', error.args[0]):
            raise exception.ScopeNotFound('Scope not found!')
        raise exception.RucioException(error.args)


def __add_files_to_archive(scope, name, files, account, ignore_duplicate=False, session=None):
    """
    Add files to archive.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param files: archive content.
    :param account: The account owner.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    # lookup for existing files
    files_query = session.query(models.DataIdentifier.scope, models.DataIdentifier.name,
                                models.DataIdentifier.bytes, models.DataIdentifier.guid,
                                models.DataIdentifier.events,
                                models.DataIdentifier.availability,
                                models.DataIdentifier.adler32, models.DataIdentifier.md5).\
        filter(models.DataIdentifier.did_type == DIDType.FILE).\
        with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle')

    file_condition = []
    for file in files:
        file_condition.append(and_(models.DataIdentifier.scope == file['scope'],
                                   models.DataIdentifier.name == file['name']))

    existing_content, existing_files = [], {}
    if ignore_duplicate:
        # lookup for existing content
        content_query = session.query(models.ConstituentAssociation.scope,
                                      models.ConstituentAssociation.name,
                                      models.ConstituentAssociation.child_scope,
                                      models.ConstituentAssociation.child_name).\
            with_hint(models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle')
        content_condition = []
        for file in files:
            content_condition.append(and_(models.ConstituentAssociation.scope == scope,
                                          models.ConstituentAssociation.name == name,
                                          models.ConstituentAssociation.child_scope == file['scope'],
                                          models.ConstituentAssociation.child_name == file['name']))
        for row in content_query.filter(or_(*content_condition)):
            existing_content.append(row)

    for row in files_query.filter(or_(*file_condition)):
        existing_files['%s:%s' % (row.scope.internal, row.name)] = {'child_scope': row.scope,
                                                                    'child_name': row.name,
                                                                    'scope': scope,
                                                                    'name': name,
                                                                    'bytes': row.bytes,
                                                                    'adler32': row.adler32,
                                                                    'md5': row.md5,
                                                                    'guid': row.guid,
                                                                    'length': row.events}

    contents = []
    new_files, existing_files_condition = [], []
    for file in files:
        did_tag = '%s:%s' % (file['scope'].internal, file['name'])
        if did_tag not in existing_files:
            # For non existing files
            # Add them to the content
            contents.append({'child_scope': file['scope'],
                             'child_name': file['name'],
                             'scope': scope,
                             'name': name,
                             'bytes': file['bytes'],
                             'adler32': file.get('adler32'),
                             'md5': file.get('md5'),
                             'guid': file.get('guid'),
                             'length': file.get('events')})

            file['constituent'] = True
            file['did_type'] = DIDType.FILE
            file['account'] = account
            for key in file.get('meta', {}):
                file[key] = file['meta'][key]
            # Prepare new file registrations
            new_files.append(file)
        else:
            # For existing files
            # Prepare the dids updates
            existing_files_condition.append(and_(models.DataIdentifier.scope == file['scope'],
                                                 models.DataIdentifier.name == file['name']))
            # Check if they are not already in the content
            if not existing_content or (scope, name, file['scope'], file['name']) not in existing_content:
                contents.append(existing_files[did_tag])

    # insert into archive_contents
    try:
        new_files and session.bulk_insert_mappings(models.DataIdentifier, new_files)
        if existing_files_condition:
            for chunk in chunks(existing_files_condition, 20):
                session.query(models.DataIdentifier).\
                    with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
                    filter(models.DataIdentifier.did_type == DIDType.FILE).\
                    filter(or_(models.DataIdentifier.constituent.is_(None), models.DataIdentifier.constituent == false())).\
                    filter(or_(*chunk)).update({'constituent': True})
        contents and session.bulk_insert_mappings(models.ConstituentAssociation, contents)
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)

    archive_did = session.query(models.DataIdentifier). \
        filter(models.DataIdentifier.did_type == DIDType.FILE). \
        filter(models.DataIdentifier.scope == scope). \
        filter(models.DataIdentifier.name == name).\
        first()
    if not archive_did.is_archive:
        # mark tha archive file as is_archive
        archive_did.is_archive = True

        # mark parent datasets as is_archive = True
        session.query(models.DataIdentifier).filter(
            exists(select([1]).prefix_with("/*+ INDEX(CONTENTS CONTENTS_CHILD_SCOPE_NAME_IDX) */", dialect="oracle")).where(
                and_(models.DataIdentifierAssociation.child_scope == scope,
                     models.DataIdentifierAssociation.child_name == name,
                     models.DataIdentifierAssociation.scope == models.DataIdentifier.scope,
                     models.DataIdentifierAssociation.name == models.DataIdentifier.name))
        ).filter(
            or_(models.DataIdentifier.is_archive.is_(None),
                models.DataIdentifier.is_archive == false())
        ).update({"is_archive": True}, synchronize_session=False)


@transactional_session
def __add_files_to_dataset(scope, name, files, account, rse_id, ignore_duplicate=False, session=None):
    """
    Add files to dataset.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param files: .
    :param account: The account owner.
    :param rse_id: The RSE id for the replicas.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    # Get metadata from dataset
    try:
        dataset_meta = validate_name(scope=scope, name=name, did_type='D')
    except Exception:
        dataset_meta = None

    if rse_id:
        rucio.core.replica.add_replicas(rse_id=rse_id, files=files, dataset_meta=dataset_meta,
                                        account=account, session=session)

    files = get_files(files=files, session=session)

    existing_content = []
    if ignore_duplicate:
        content_query = session.query(models.DataIdentifierAssociation.scope,
                                      models.DataIdentifierAssociation.name,
                                      models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name).\
            with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
        content_condition = []
        for file in files:
            content_condition.append(and_(models.DataIdentifierAssociation.scope == scope,
                                          models.DataIdentifierAssociation.name == name,
                                          models.DataIdentifierAssociation.child_scope == file['scope'],
                                          models.DataIdentifierAssociation.child_name == file['name']))
        for row in content_query.filter(or_(*content_condition)):
            existing_content.append(row)

    contents = []
    added_archives_condition = []
    for file in files:
        if not existing_content or (scope, name, file['scope'], file['name']) not in existing_content:
            contents.append({'scope': scope, 'name': name, 'child_scope': file['scope'],
                             'child_name': file['name'], 'bytes': file['bytes'],
                             'adler32': file.get('adler32'),
                             'guid': file['guid'], 'events': file['events'],
                             'md5': file.get('md5'), 'did_type': DIDType.DATASET,
                             'child_type': DIDType.FILE, 'rule_evaluation': True})
            added_archives_condition.append(
                and_(models.DataIdentifier.scope == file['scope'],
                     models.DataIdentifier.name == file['name'],
                     models.DataIdentifier.is_archive == true()))

    # if any of the attached files is an archive, set is_archive = True on the dataset
    if session.query(models.DataIdentifier). \
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'). \
            filter(or_(*added_archives_condition)). \
            first() is not None:
        session.query(models.DataIdentifier). \
            filter(models.DataIdentifier.scope == scope). \
            filter(models.DataIdentifier.name == name). \
            filter(or_(models.DataIdentifier.is_archive.is_(None),
                       models.DataIdentifier.is_archive == false())). \
            update({'is_archive': True})

    try:
        contents and session.bulk_insert_mappings(models.DataIdentifierAssociation, contents)
        session.flush()
    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-02291: integrity constraint .*CONTENTS_CHILD_ID_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', error.args[0]) \
                or match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]) \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint.*', error.args[0]):
            raise exception.DataIdentifierNotFound("Data identifier not found")
        elif match('.*IntegrityError.*ORA-00001: unique constraint .*CONTENTS_PK.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*UNIQUE constraint failed: contents.scope, contents.name, contents.child_scope, contents.child_name.*', error.args[0])\
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry .*for key.*PRIMARY.*', error.args[0]) \
                or match('.*duplicate entry.*key.*PRIMARY.*', error.args[0]) \
                or match('.*IntegrityError.*columns? .*not unique.*', error.args[0]):
            raise exception.FileAlreadyExists(error.args)
        else:
            raise exception.RucioException(error.args)


@transactional_session
def __add_collections_to_container(scope, name, collections, account, session):
    """
    Add collections (datasets or containers) to container.

    :param scope: The scope name.
    :param name: The container name.
    :param collections: .
    :param account: The account owner.
    :param session: The database session in use.
    """

    condition = []
    for cond in collections:

        if (scope == cond['scope']) and (name == cond['name']):
            raise exception.UnsupportedOperation('Self-append is not valid!')

        condition.append(and_(models.DataIdentifier.scope == cond['scope'],
                              models.DataIdentifier.name == cond['name']))

    available_dids = {}
    child_type = None
    for row in session.query(models.DataIdentifier.scope,
                             models.DataIdentifier.name,
                             models.DataIdentifier.did_type).with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').filter(or_(*condition)):

        if row.did_type == DIDType.FILE:
            raise exception.UnsupportedOperation("Adding a file (%s:%s) to a container (%s:%s) is forbidden" % (row.scope, row.name, scope, name))

        if not child_type:
            child_type = row.did_type

        available_dids['%s:%s' % (row.scope.internal, row.name)] = row.did_type

        if child_type != row.did_type:
            raise exception.UnsupportedOperation("Mixed collection is not allowed: '%s:%s' is a %s(expected type: %s)" % (row.scope, row.name, row.did_type, child_type))

    for c in collections:
        did_asso = models.DataIdentifierAssociation(scope=scope, name=name, child_scope=c['scope'], child_name=c['name'],
                                                    did_type=DIDType.CONTAINER, child_type=available_dids.get('%s:%s' % (c['scope'].internal, c['name'])), rule_evaluation=True)
        did_asso.save(session=session, flush=False)
        # Send AMI messages
        if child_type == DIDType.CONTAINER:
            chld_type = 'CONTAINER'
        elif child_type == DIDType.DATASET:
            chld_type = 'DATASET'
        else:
            chld_type = 'UNKNOWN'

        message = {'account': account.external,
                   'scope': scope.external,
                   'name': name,
                   'childscope': c['scope'].external,
                   'childname': c['name'],
                   'childtype': chld_type}
        if account.vo != 'def':
            message['vo'] = account.vo

        add_message('REGISTER_CNT', message, session=session)
    try:
        session.flush()
    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-02291: integrity constraint .*CONTENTS_CHILD_ID_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', error.args[0]) \
                or match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]) \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint.*', error.args[0]):
            raise exception.DataIdentifierNotFound("Data identifier not found")
        elif match('.*IntegrityError.*ORA-00001: unique constraint .*CONTENTS_PK.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry .*for key.*PRIMARY.*', error.args[0]) \
                or match('.*IntegrityError.*columns? scope.*name.*child_scope.*child_name.*not unique.*', error.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.* UNIQUE constraint failed: contents.scope, contents.name, contents.child_scope, contents.child_name.*', error.args[0]):
            raise exception.DuplicateContent(error.args)
        raise exception.RucioException(error.args)


@transactional_session
def attach_dids(scope, name, dids, account, rse_id=None, session=None):
    """
    Append data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param account: The account owner.
    :param rse_id: The RSE id for the replicas.
    :param session: The database session in use.
    """
    return attach_dids_to_dids(attachments=[{'scope': scope, 'name': name, 'dids': dids, 'rse_id': rse_id}], account=account, session=session)


@transactional_session
def attach_dids_to_dids(attachments, account, ignore_duplicate=False, session=None):
    """
    Append content to dids.

    :param attachments: The contents.
    :param account: The account.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    parent_did_condition = list()
    parent_dids = list()
    for attachment in attachments:
        try:
            parent_did = session.query(models.DataIdentifier).filter_by(scope=attachment['scope'], name=attachment['name']).\
                with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
                one()

            if parent_did.did_type == DIDType.FILE:
                # check if parent file has the archive extension
                if is_archive(attachment['name']):
                    __add_files_to_archive(scope=attachment['scope'],
                                           name=attachment['name'],
                                           files=attachment['dids'],
                                           account=account,
                                           ignore_duplicate=ignore_duplicate,
                                           session=session)
                    return
                raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is a file" % attachment)

            elif not parent_did.is_open:
                raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is closed" % attachment)

            elif parent_did.did_type == DIDType.DATASET:
                __add_files_to_dataset(scope=attachment['scope'], name=attachment['name'],
                                       files=attachment['dids'], account=account,
                                       ignore_duplicate=ignore_duplicate,
                                       rse_id=attachment.get('rse_id'),
                                       session=session)

            elif parent_did.did_type == DIDType.CONTAINER:
                __add_collections_to_container(scope=attachment['scope'],
                                               name=attachment['name'],
                                               collections=attachment['dids'],
                                               account=account, session=session)

            parent_did_condition.append(and_(models.DataIdentifier.scope == parent_did.scope,
                                             models.DataIdentifier.name == parent_did.name))

            parent_dids.append({'scope': parent_did.scope,
                                'name': parent_did.name,
                                'rule_evaluation_action': DIDReEvaluation.ATTACH})
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (attachment['scope'], attachment['name']))

        session.bulk_insert_mappings(models.UpdatedDID, parent_dids)


@transactional_session
def delete_dids(dids, account, expire_rules=False, session=None, logger=logging.log):
    """
    Delete data identifiers

    :param dids:          The list of dids to delete.
    :param account:       The account.
    :param expire_rules:  Expire large rules instead of deleting them right away. This should only be used in Undertaker mode, as it can be that
                          the method returns normally, but a did was not deleted; This trusts in the fact that the undertaker will retry an
                          expired did.
    :param session:       The database session in use.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    """
    rule_id_clause, content_clause = [], []
    parent_content_clause, did_clause = [], []
    collection_replica_clause, file_clause = [], []
    not_purge_replicas = []
    did_followed_clause = []
    metadata_to_delete = []

    for did in dids:
        logger(logging.INFO, 'Removing did %(scope)s:%(name)s (%(did_type)s)' % did)
        if did['did_type'] == DIDType.FILE:
            file_clause.append(and_(models.DataIdentifier.scope == did['scope'], models.DataIdentifier.name == did['name']))
        else:
            did_clause.append(and_(models.DataIdentifier.scope == did['scope'], models.DataIdentifier.name == did['name']))
            content_clause.append(and_(models.DataIdentifierAssociation.scope == did['scope'], models.DataIdentifierAssociation.name == did['name']))
            collection_replica_clause.append(and_(models.CollectionReplica.scope == did['scope'],
                                                  models.CollectionReplica.name == did['name']))
            did_followed_clause.append(and_(models.DidsFollowed.scope == did['scope'], models.DidsFollowed.name == did['name']))

        # ATLAS LOCALGROUPDISK Archive policy
        if did['did_type'] == DIDType.DATASET and did['scope'].external != 'archive':
            try:
                rucio.core.rule.archive_localgroupdisk_datasets(scope=did['scope'], name=did['name'], session=session)
            except exception.UndefinedPolicy:
                pass

        if did['purge_replicas'] is False:
            not_purge_replicas.append((did['scope'], did['name']))

            # Archive content
            # Disable for postgres
            insert_content_history(content_clause=[and_(models.DataIdentifierAssociation.scope == did['scope'],
                                                        models.DataIdentifierAssociation.name == did['name'])],
                                   did_created_at=did.get('created_at'),
                                   session=session)

        parent_content_clause.append(and_(models.DataIdentifierAssociation.child_scope == did['scope'], models.DataIdentifierAssociation.child_name == did['name']))
        rule_id_clause.append(and_(models.ReplicationRule.scope == did['scope'], models.ReplicationRule.name == did['name']))

        if session.bind.dialect.name == 'oracle':
            oracle_version = int(session.connection().connection.version.split('.')[0])
            if oracle_version >= 12:
                metadata_to_delete.append(and_(models.DidMeta.scope == did['scope'], models.DidMeta.name == did['name']))
        else:
            metadata_to_delete.append(and_(models.DidMeta.scope == did['scope'], models.DidMeta.name == did['name']))

        # Send message
        message = {'account': account.external,
                   'scope': did['scope'].external,
                   'name': did['name']}
        if did['scope'].vo != 'def':
            message['vo'] = did['scope'].vo

        add_message('ERASE', message, session=session)
    # Delete rules on did
    skip_deletion = False  # Skip deletion in case of expiration of a rule
    if rule_id_clause:
        with record_timer_block('undertaker.rules'):
            for (rule_id, scope, name, rse_expression, locks_ok_cnt, locks_replicating_cnt, locks_stuck_cnt) in session.query(models.ReplicationRule.id,
                                                                                                                              models.ReplicationRule.scope,
                                                                                                                              models.ReplicationRule.name,
                                                                                                                              models.ReplicationRule.rse_expression,
                                                                                                                              models.ReplicationRule.locks_ok_cnt,
                                                                                                                              models.ReplicationRule.locks_replicating_cnt,
                                                                                                                              models.ReplicationRule.locks_stuck_cnt).filter(or_(*rule_id_clause)):
                logger(logging.DEBUG, 'Removing rule %s for did %s:%s on RSE-Expression %s' % (str(rule_id), scope, name, rse_expression))

                # Propagate purge_replicas from did to rules
                if (scope, name) in not_purge_replicas:
                    purge_replicas = False
                else:
                    purge_replicas = True
                if expire_rules and locks_ok_cnt + locks_replicating_cnt + locks_stuck_cnt > int(config_core.get('undertaker', 'expire_rules_locks_size', default=10000, session=session)):
                    # Expire the rule (soft=True)
                    rucio.core.rule.delete_rule(rule_id=rule_id, purge_replicas=purge_replicas, soft=True, delete_parent=True, nowait=True, session=session)
                    # Update expiration of did
                    set_metadata(scope=scope, name=name, key='lifetime', value=3600 * 24, session=session)
                    skip_deletion = True
                else:
                    rucio.core.rule.delete_rule(rule_id=rule_id, purge_replicas=purge_replicas, delete_parent=True, nowait=True, session=session)

    if skip_deletion:
        return

    # Detach from parent dids:
    existing_parent_dids = False
    if parent_content_clause:
        with record_timer_block('undertaker.parent_content'):
            for parent_did in session.query(models.DataIdentifierAssociation).filter(or_(*parent_content_clause)):
                existing_parent_dids = True
                detach_dids(scope=parent_did.scope, name=parent_did.name, dids=[{'scope': parent_did.child_scope, 'name': parent_did.child_name}], session=session)

    # Remove content
    if content_clause:
        with record_timer_block('undertaker.content'):
            rowcount = session.query(models.DataIdentifierAssociation).filter(or_(*content_clause)).\
                delete(synchronize_session=False)
        record_counter(counters='undertaker.content.rowcount', delta=rowcount)

    # Remove CollectionReplica
    if collection_replica_clause:
        with record_timer_block('undertaker.dids'):
            rowcount = session.query(models.CollectionReplica).filter(or_(*collection_replica_clause)).\
                delete(synchronize_session=False)

    # Remove generic did metadata
    if metadata_to_delete:
        if session.bind.dialect.name == 'oracle':
            oracle_version = int(session.connection().connection.version.split('.')[0])
            if oracle_version >= 12:
                with record_timer_block('undertaker.did_meta'):
                    rowcount = session.query(models.DidMeta).filter(or_(*metadata_to_delete)).\
                        delete(synchronize_session=False)
        else:
            with record_timer_block('undertaker.did_meta'):
                rowcount = session.query(models.DidMeta).filter(or_(*metadata_to_delete)).\
                    delete(synchronize_session=False)

    # remove data identifier
    if existing_parent_dids:
        # Exit method early to give Judge time to remove locks (Otherwise, due to foreign keys, did removal does not work
        logger(logging.DEBUG, 'Leaving delete_dids early for Judge-Evaluator checks')
        return

    if did_clause:
        with record_timer_block('undertaker.dids'):
            rowcount = session.query(models.DataIdentifier).filter(or_(*did_clause)).\
                filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET)).\
                delete(synchronize_session=False)

    if did_followed_clause:
        with record_timer_block('undertaker.dids'):
            rowcount = session.query(models.DidsFollowed).filter(or_(*did_followed_clause)).\
                delete(synchronize_session=False)

    if file_clause:
        rowcount = session.query(models.DataIdentifier).filter(or_(*file_clause)).\
            filter(models.DataIdentifier.did_type == DIDType.FILE).\
            update({'expired_at': None}, synchronize_session=False)


@transactional_session
def detach_dids(scope, name, dids, session=None):
    """
    Detach data identifier

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param session: The database session in use.
    """
    # Row Lock the parent did
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
        filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET))
    try:
        did = query.one()
        # Mark for rule re-evaluation
        models.UpdatedDID(scope=scope, name=name, rule_evaluation_action=DIDReEvaluation.DETACH).save(session=session, flush=False)
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    # TODO: should judge target did's status: open, monotonic, close.
    query_all = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name)
    if query_all.first() is None:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' has no child data identifiers." % locals())
    for source in dids:
        if (scope == source['scope']) and (name == source['name']):
            raise exception.UnsupportedOperation('Self-detach is not valid.')
        child_scope = source['scope']
        child_name = source['name']
        associ_did = query_all.filter_by(child_scope=child_scope, child_name=child_name).first()
        if associ_did is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(child_scope)s:%(child_name)s' not found under '%(scope)s:%(name)s'" % locals())

        child_type = associ_did.child_type
        child_size = associ_did.bytes
        child_events = associ_did.events
        if did.length:
            did.length -= 1
        if did.bytes and child_size:
            did.bytes -= child_size
        if did.events and child_events:
            did.events -= child_events
        associ_did.delete(session=session)

        # Archive contents
        # If reattach happens, merge the latest due to primary key constraint
        new_detach = models.DataIdentifierAssociationHistory(scope=associ_did.scope,
                                                             name=associ_did.name,
                                                             child_scope=associ_did.child_scope,
                                                             child_name=associ_did.child_name,
                                                             did_type=associ_did.did_type,
                                                             child_type=associ_did.child_type,
                                                             bytes=associ_did.bytes,
                                                             adler32=associ_did.adler32,
                                                             md5=associ_did.md5,
                                                             guid=associ_did.guid,
                                                             events=associ_did.events,
                                                             rule_evaluation=associ_did.rule_evaluation,
                                                             did_created_at=did.created_at,
                                                             created_at=associ_did.created_at,
                                                             updated_at=associ_did.updated_at,
                                                             deleted_at=datetime.utcnow())
        new_detach.save(session=session, flush=False)

        # Send message for AMI. To be removed in the future when they use the DETACH messages
        if did.did_type == DIDType.CONTAINER:
            if child_type == DIDType.CONTAINER:
                chld_type = 'CONTAINER'
            elif child_type == DIDType.DATASET:
                chld_type = 'DATASET'
            else:
                chld_type = 'UNKNOWN'

            message = {'scope': scope.external,
                       'name': name,
                       'childscope': source['scope'].external,
                       'childname': source['name'],
                       'childtype': chld_type}
            if scope.vo != 'def':
                message['vo'] = scope.vo

            add_message('ERASE_CNT', message, session=session)

        message = {'scope': scope.external,
                   'name': name,
                   'did_type': str(did.did_type),
                   'child_scope': source['scope'].external,
                   'child_name': str(source['name']),
                   'child_type': str(child_type)}
        if scope.vo != 'def':
            message['vo'] = scope.vo

        add_message('DETACH', message, session=session)


@stream_session
def list_new_dids(did_type, thread=None, total_threads=None, chunk_size=1000, session=None):
    """
    List recent identifiers.

    :param did_type : The DID type.
    :param thread: The assigned thread for this necromancer.
    :param total_threads: The total number of threads of all necromancers.
    :param chunk_size: Number of requests to return per yield.
    :param session: The database session in use.
    """

    stmt = select([1]).\
        prefix_with("/*+ INDEX(RULES ATLAS_RUCIO.RULES_SCOPE_NAME_IDX) */",
                    dialect='oracle').\
        where(and_(models.DataIdentifier.scope == models.ReplicationRule.scope,
                   models.DataIdentifier.name == models.ReplicationRule.name,
                   models.ReplicationRule.state == RuleState.INJECT))

    query = session.query(models.DataIdentifier).\
        with_hint(models.DataIdentifier, "index(dids DIDS_IS_NEW_IDX)", 'oracle').\
        filter_by(is_new=True).\
        filter(~exists(stmt))

    if did_type:
        if isinstance(did_type, string_types):
            query = query.filter_by(did_type=DIDType[did_type])
        elif isinstance(did_type, Enum):
            query = query.filter_by(did_type=did_type)

    query = filter_thread_work(session=session, query=query, total_threads=total_threads, thread_id=thread, hash_variable='name')

    row_count = 0
    for chunk in query.yield_per(10):
        row_count += 1
        if row_count <= chunk_size:
            yield {'scope': chunk.scope, 'name': chunk.name, 'did_type': chunk.did_type}  # TODO Change this to the proper filebytes [RUCIO-199]
        else:
            break


@transactional_session
def set_new_dids(dids, new_flag, session=None):
    """
    Set/reset the flag new

    :param dids: A list of dids
    :param new_flag: A boolean to flag new DIDs.
    :param session: The database session in use.
    """
    if session.bind.dialect.name == 'postgresql':
        new_flag = bool(new_flag)
    for did in dids:
        try:

            rowcount = session.query(models.DataIdentifier).\
                filter_by(scope=did['scope'], name=did['name']).\
                update({'is_new': new_flag}, synchronize_session=False)
            if not rowcount:
                raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (did['scope'], did['name']))
        except DatabaseError as error:
            raise exception.DatabaseException('%s : Cannot update %s:%s' % (error.args[0], did['scope'], did['name']))
    try:
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args[0])
    except DatabaseError as error:
        raise exception.RucioException(error.args[0])
    return True


@stream_session
def list_content(scope, name, session=None):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        query = session.query(models.DataIdentifierAssociation).\
            with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').\
            filter_by(scope=scope, name=name)
        for tmp_did in query.yield_per(5):
            yield {'scope': tmp_did.child_scope, 'name': tmp_did.child_name, 'type': tmp_did.child_type,
                   'bytes': tmp_did.bytes, 'adler32': tmp_did.adler32, 'md5': tmp_did.md5}
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@stream_session
def list_content_history(scope, name, session=None):
    """
    List data identifier contents history.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        # query = session.query(models.DataIdentifierAssociationHistory).\
        #    with_hint(models.DataIdentifierAssociationHistory,
        #              "INDEX(CONTENTS_HISTORY CONTENTS_HIST_PK)", 'oracle').\
        #    filter_by(scope=scope, name=name)
        query = session.query(models.DataIdentifierAssociationHistory).\
            filter_by(scope=scope, name=name)
        for tmp_did in query.yield_per(5):
            yield {'scope': tmp_did.child_scope, 'name': tmp_did.child_name,
                   'type': tmp_did.child_type,
                   'bytes': tmp_did.bytes, 'adler32': tmp_did.adler32, 'md5': tmp_did.md5,
                   'deleted_at': tmp_did.deleted_at, 'created_at': tmp_did.created_at,
                   'updated_at': tmp_did.updated_at}
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@stream_session
def list_parent_dids(scope, name, session=None):
    """
    List parent datasets and containers of a did.

    :param scope:     The scope.
    :param name:      The name.
    :param session:   The database session.
    :returns:         List of dids.
    :rtype:           Generator.
    """

    query = session.query(models.DataIdentifierAssociation.scope,
                          models.DataIdentifierAssociation.name,
                          models.DataIdentifierAssociation.did_type).filter_by(child_scope=scope, child_name=name)
    for did in query.yield_per(5):
        yield {'scope': did.scope, 'name': did.name, 'type': did.did_type}


@stream_session
def list_all_parent_dids(scope, name, session=None):
    """
    List all parent datasets and containers of a did, no matter on what level.

    :param scope:     The scope.
    :param name:      The name.
    :param session:   The database session.
    :returns:         List of dids.
    :rtype:           Generator.
    """

    query = session.query(models.DataIdentifierAssociation.scope,
                          models.DataIdentifierAssociation.name,
                          models.DataIdentifierAssociation.did_type).filter_by(child_scope=scope, child_name=name)
    for did in query.yield_per(5):
        yield {'scope': did.scope, 'name': did.name, 'type': did.did_type}
        # Note that only Python3 supports recursive yield, that's the reason to do the nested for.
        for pdid in list_all_parent_dids(scope=did.scope, name=did.name, session=session):
            yield {'scope': pdid['scope'], 'name': pdid['name'], 'type': pdid['type']}


@transactional_session
def list_child_datasets(scope, name, session=None):
    """
    List all child datasets of a container.

    :param scope:     The scope.
    :param name:      The name.
    :param session:   The database session
    :returns:         List of dids
    :rtype:           Generator
    """

    result = []
    query = session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.child_type).filter(models.DataIdentifierAssociation.scope == scope,
                                                                              models.DataIdentifierAssociation.name == name,
                                                                              models.DataIdentifierAssociation.child_type != DIDType.FILE)
    query = query.with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
    for child_scope, child_name, child_type in query.yield_per(5):
        if child_type == DIDType.CONTAINER:
            result.extend(list_child_datasets(scope=child_scope, name=child_name, session=session))
        else:
            result.append({'scope': child_scope, 'name': child_name, 'type': child_type})

    # remove duplicate entries
    result = {(elem['scope'], elem['name']): elem for elem in result}.values()

    return result


@stream_session
def list_files(scope, name, long=False, session=None):
    """
    List data identifier file contents.

    :param scope:      The scope name.
    :param name:       The data identifier name.
    :param long:       A boolean to choose if more metadata are returned or not.
    :param session:    The database session in use.
    """
    try:
        did = session.query(models.DataIdentifier.scope, models.DataIdentifier.name,
                            models.DataIdentifier.bytes, models.DataIdentifier.adler32,
                            models.DataIdentifier.guid, models.DataIdentifier.events,
                            models.DataIdentifier.lumiblocknr,
                            models.DataIdentifier.did_type).\
            filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
            one()

        if did[7] == DIDType.FILE:
            if long:
                yield {'scope': did[0], 'name': did[1], 'bytes': did[2],
                       'adler32': did[3], 'guid': did[4] and did[4].upper(),
                       'events': did[5], 'lumiblocknr': did[6]}
            else:
                yield {'scope': did[0], 'name': did[1], 'bytes': did[2],
                       'adler32': did[3], 'guid': did[4] and did[4].upper(),
                       'events': did[5]}
        else:
            cnt_query = session.\
                query(models.DataIdentifierAssociation.child_scope,
                      models.DataIdentifierAssociation.child_name,
                      models.DataIdentifierAssociation.child_type).\
                with_hint(models.DataIdentifierAssociation,
                          "INDEX(CONTENTS CONTENTS_PK)", 'oracle')

            if long:
                dst_cnt_query = session.\
                    query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.child_type,
                          models.DataIdentifierAssociation.bytes,
                          models.DataIdentifierAssociation.adler32,
                          models.DataIdentifierAssociation.guid,
                          models.DataIdentifierAssociation.events,
                          models.DataIdentifier.lumiblocknr).\
                    with_hint(models.DataIdentifierAssociation,
                              "INDEX_RS_ASC(DIDS DIDS_PK) INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                              "oracle").\
                    filter(and_(models.DataIdentifier.scope == models.DataIdentifierAssociation.child_scope,
                                models.DataIdentifier.name == models.DataIdentifierAssociation.child_name))
            else:
                dst_cnt_query = session.\
                    query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.child_type,
                          models.DataIdentifierAssociation.bytes,
                          models.DataIdentifierAssociation.adler32,
                          models.DataIdentifierAssociation.guid,
                          models.DataIdentifierAssociation.events,
                          bindparam("lumiblocknr", None)).\
                    with_hint(models.DataIdentifierAssociation,
                              "INDEX(CONTENTS CONTENTS_PK)", 'oracle')

            dids = [(scope, name, did[7]), ]
            while dids:
                s, n, t = dids.pop()
                if t == DIDType.DATASET:
                    query = dst_cnt_query.\
                        filter(and_(models.DataIdentifierAssociation.scope == s,
                                    models.DataIdentifierAssociation.name == n))

                    for child_scope, child_name, child_type, bytes, adler32, guid, events, lumiblocknr in query.yield_per(500):
                        if long:
                            yield {'scope': child_scope, 'name': child_name,
                                   'bytes': bytes, 'adler32': adler32,
                                   'guid': guid and guid.upper(),
                                   'events': events,
                                   'lumiblocknr': lumiblocknr}
                        else:
                            yield {'scope': child_scope, 'name': child_name,
                                   'bytes': bytes, 'adler32': adler32,
                                   'guid': guid and guid.upper(),
                                   'events': events}
                else:
                    for child_scope, child_name, child_type in cnt_query.filter_by(scope=s, name=n).yield_per(500):
                        dids.append((child_scope, child_name, child_type))

    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@stream_session
def scope_list(scope, name=None, recursive=False, session=None):
    """
    List data identifiers in a scope.

    :param scope: The scope name.
    :param session: The database session in use.
    :param name: The data identifier name.
    :param recursive: boolean, True or False.
    """
    # TODO= Perf. tuning of the method
    # query = session.query(models.DataIdentifier).filter_by(scope=scope, deleted=False)
    # for did in query.yield_per(5):
    #    yield {'scope': did.scope, 'name': did.name, 'type': did.did_type, 'parent': None, 'level': 0}

    def __topdids(scope):
        c = session.query(models.DataIdentifierAssociation.child_name).filter_by(scope=scope, child_scope=scope)
        q = session.query(models.DataIdentifier.name, models.DataIdentifier.did_type, models.DataIdentifier.bytes).filter_by(scope=scope)  # add type
        s = q.filter(not_(models.DataIdentifier.name.in_(c))).order_by(models.DataIdentifier.name)
        for row in s.yield_per(5):
            if row.did_type == DIDType.FILE:
                yield {'scope': scope, 'name': row.name, 'type': row.did_type, 'parent': None, 'level': 0, 'bytes': row.bytes}
            else:
                yield {'scope': scope, 'name': row.name, 'type': row.did_type, 'parent': None, 'level': 0, 'bytes': None}

    def __diddriller(pdid):
        query_associ = session.query(models.DataIdentifierAssociation).filter_by(scope=pdid['scope'], name=pdid['name'])
        for row in query_associ.order_by('child_name').yield_per(5):
            parent = {'scope': pdid['scope'], 'name': pdid['name']}
            cdid = {'scope': row.child_scope, 'name': row.child_name, 'type': row.child_type, 'parent': parent, 'level': pdid['level'] + 1}
            yield cdid
            if cdid['type'] != DIDType.FILE and recursive:
                for did in __diddriller(cdid):
                    yield did

    if name is None:
        topdids = __topdids(scope)
    else:
        topdids = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).first()
        if topdids is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        topdids = [{'scope': topdids.scope, 'name': topdids.name, 'type': topdids.did_type, 'parent': None, 'level': 0}]

    if name is None:
        for topdid in topdids:
            yield topdid
            if recursive:
                for did in __diddriller(topdid):
                    yield did
    else:
        for topdid in topdids:
            for did in __diddriller(topdid):
                yield did


@read_session
def get_did(scope, name, dynamic=False, session=None):
    """
    Retrieve a single data identifier.

    :param scope:    The scope name.
    :param name:     The data identifier name.
    :param dynamic:  Dynamically resolve the bytes and length of the did.
    :param session:  The database session in use.
    """
    try:
        result = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').one()
        if result.did_type == DIDType.FILE:
            return {'scope': result.scope, 'name': result.name, 'type': result.did_type,
                    'account': result.account, 'bytes': result.bytes, 'length': 1,
                    'md5': result.md5, 'adler32': result.adler32}
        else:
            if dynamic:
                bytes, length, events = __resolve_bytes_length_events_did(scope=scope, name=name, session=session)
                # replace None value for bytes with zero
                if bytes is None:
                    bytes = 0
            else:
                bytes, length = result.bytes, result.length
            return {'scope': result.scope, 'name': result.name, 'type': result.did_type,
                    'account': result.account, 'open': result.is_open,
                    'monotonic': result.monotonic, 'expired_at': result.expired_at,
                    'length': length, 'bytes': bytes}
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@read_session
def get_files(files, session=None):
    """
    Retrieve a list of files.

    :param files: A list of files (dictionaries).
    :param session: The database session in use.
    """
    files_query = session.query(models.DataIdentifier.scope, models.DataIdentifier.name,
                                models.DataIdentifier.bytes, models.DataIdentifier.guid,
                                models.DataIdentifier.events, models.DataIdentifier.availability,
                                models.DataIdentifier.adler32, models.DataIdentifier.md5).\
        filter(models.DataIdentifier.did_type == DIDType.FILE).\
        with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle')
    file_condition = []
    for file in files:
        file_condition.append(and_(models.DataIdentifier.scope == file['scope'], models.DataIdentifier.name == file['name']))

    rows = []
    for row in files_query.filter(or_(*file_condition)):
        file = row._asdict()
        rows.append(file)
        if file['availability'] == DIDAvailability.LOST:
            raise exception.UnsupportedOperation('File %s:%s is LOST and cannot be attached' % (file['scope'], file['name']))
        # Check meta-data, if provided
        for f in files:
            if f['name'] == file['name'] and f['scope'] == file['scope']:
                for key in ['bytes', 'adler32', 'md5']:
                    if key in f and str(f.get(key)) != str(file[key]):
                        raise exception.FileConsistencyMismatch(key + " mismatch for '%(scope)s:%(name)s': " % file + str(f.get(key)) + '!=' + str(file[key]))
                break

    if len(rows) != len(files):
        for file in files:
            found = False
            for row in rows:
                if row['scope'] == file['scope'] and row['name'] == file['name']:
                    found = True
                    break
            if not found:
                raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % file)
    return rows


@transactional_session
def set_metadata(scope, name, key, value, type=None, did=None,
                 recursive=False, session=None):
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
    did_meta_plugins.set_metadata(scope=scope, name=name, key=key, value=value, recursive=recursive, session=session)


@transactional_session
def set_metadata_bulk(scope, name, meta, recursive=False, session=None):
    """
    Add metadata to data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param meta: the key-values.
    :param recursive: Option to propagate the metadata change to content.
    :param session: The database session in use.
    """
    did_meta_plugins.set_metadata_bulk(scope=scope, name=name, meta=meta, recursive=recursive, session=session)


@read_session
def get_metadata(scope, name, plugin='DID_COLUMN', session=None):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.

    :returns: List of HARDCODED metadata for did.
    """
    return did_meta_plugins.get_metadata(scope, name, plugin=plugin, session=session)


@stream_session
def get_metadata_bulk(dids, session=None):
    """
    Get metadata for a list of dids
    :param dids: A list of dids.
    :param session: The database session in use.
    """
    condition = []
    for did in dids:
        condition.append(and_(models.DataIdentifier.scope == did['scope'],
                              models.DataIdentifier.name == did['name']))

    try:
        for chunk in chunks(condition, 50):
            for row in session.query(models.DataIdentifier).with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').filter(or_(*chunk)):
                data = {}
                for column in row.__table__.columns:
                    data[column.name] = getattr(row, column.name)
                yield data
    except NoResultFound:
        raise exception.DataIdentifierNotFound('No Data Identifiers found')


@transactional_session
def delete_metadata(scope, name, key, session=None):
    """
    Delete a key from the metadata column

    :param scope: the scope of did
    :param name: the name of the did
    :param key: the key to be deleted
    """
    did_meta_plugins.delete_metadata(scope, name, key, session=session)


@transactional_session
def set_status(scope, name, session=None, **kwargs):
    """
    Set data identifier status

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    :param kwargs:  Keyword arguments of the form status_name=value.
    """
    statuses = ['open', ]

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
        with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
        filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET))
    values = {}
    for k in kwargs:
        if k not in statuses:
            raise exception.UnsupportedStatus("The status %(k)s is not a valid data identifier status." % locals())
        if k == 'open':
            if not kwargs[k]:
                query = query.filter_by(is_open=True).filter(models.DataIdentifier.did_type != DIDType.FILE)
                values['is_open'], values['closed_at'] = False, datetime.utcnow()
                values['bytes'], values['length'], values['events'] = __resolve_bytes_length_events_did(scope=scope, name=name, session=session)
                # Update datasetlocks as well
                session.query(models.DatasetLock).filter_by(scope=scope, name=name).update({'length': values['length'], 'bytes': values['bytes']})

                # Generate a message
                message = {'scope': scope.external,
                           'name': name,
                           'bytes': values['bytes'],
                           'length': values['length'],
                           'events': values['events']}
                if scope.vo != 'def':
                    message['vo'] = scope.vo

                add_message('CLOSE', message, session=session)

            else:
                # Set status to open only for privileged accounts
                query = query.filter_by(is_open=False).filter(models.DataIdentifier.did_type != DIDType.FILE)
                values['is_open'] = True

                message = {'scope': scope.external, 'name': name}
                if scope.vo != 'def':
                    message['vo'] = scope.vo
                add_message('OPEN', message, session=session)

    rowcount = query.update(values, synchronize_session='fetch')

    if not rowcount:
        query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)
        try:
            query.one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        raise exception.UnsupportedOperation("The status of the data identifier '%(scope)s:%(name)s' cannot be changed" % locals())
    else:
        # Generate callbacks
        if not values['is_open']:
            rules_on_ds = session.query(models.ReplicationRule).filter_by(scope=scope, name=name).all()
            for rule in rules_on_ds:
                rucio.core.rule.generate_rule_notifications(rule=rule, session=session)


@stream_session
def list_dids(scope, filters, type='collection', ignore_case=False, limit=None,
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
                                     like(v.replace('*', '%').replace('_', r'\_'),
                                          escape='\\'))
            else:
                query = query.filter(getattr(models.DataIdentifier, k).
                                     like(v.replace('*', '%').replace('_', r'\_'), escape='\\'))
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
        for scope, name, did_type, bytes, length in query.yield_per(100):
            if (did_type == DIDType.CONTAINER or did_type == DIDType.DATASET):
                collections_content += [did for did in list_content(scope=scope, name=name)]

        # List DIDs again to use filter
        for did in collections_content:
            filters['name'] = did['name']
            for result in list_dids(scope=did['scope'], filters=filters, recursive=True, type=type, limit=limit, offset=offset, long=long, session=session):
                yield result

    if long:
        for scope, name, did_type, bytes, length in query.yield_per(5):
            yield {'scope': scope,
                   'name': name,
                   'did_type': did_type.name,
                   'bytes': bytes,
                   'length': length}
    else:
        for scope, name, did_type, bytes, length in query.yield_per(5):
            yield name


@read_session
def list_dids_extended(scope, filters, type='collection', ignore_case=False, limit=None,
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
    return did_meta_plugins.list_dids(scope, filters, type, ignore_case, limit, offset, long, recursive, session=session)


@read_session
def get_did_atime(scope, name, session=None):
    """
    Get the accessed_at timestamp for a did. Just for testing.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    return session.query(models.DataIdentifier.accessed_at).filter_by(scope=scope, name=name).one()[0]


@read_session
def get_did_access_cnt(scope, name, session=None):
    """
    Get the access_cnt for a did. Just for testing.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    return session.query(models.DataIdentifier.access_cnt).filter_by(scope=scope, name=name).one()[0]


@stream_session
def get_dataset_by_guid(guid, session=None):
    """
    Get the parent datasets for a given GUID.
    :param guid: The GUID.
    :param session: Database session to use.

    :returns: A did.
    """
    query = session.query(models.DataIdentifier).filter_by(guid=guid, did_type=DIDType.FILE).with_hint(models.ReplicaLock, "INDEX(DIDS_GUIDS_IDX)", 'oracle')
    try:
        r = query.one()
        datasets = session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name).filter_by(child_scope=r.scope, child_name=r.name).\
            with_hint(models.DataIdentifierAssociation,
                      "INDEX(CONTENTS CONTENTS_CHILD_SCOPE_NAME_IDX)", 'oracle')
    except NoResultFound:
        raise exception.DataIdentifierNotFound("No file associated to GUID : %s" % guid)
    for tmp_did in datasets.yield_per(5):
        yield {'scope': tmp_did.scope, 'name': tmp_did.name}


@transactional_session
def touch_dids(dids, session=None):
    """
    Update the accessed_at timestamp and the access_cnt of the given dids.

    :param replicas: the list of dids.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """

    now = datetime.utcnow()
    none_value = None
    try:
        for did in dids:
            session.query(models.DataIdentifier).\
                filter_by(scope=did['scope'], name=did['name'], did_type=did['type']).\
                update({'accessed_at': did.get('accessed_at') or now,
                        'access_cnt': case([(models.DataIdentifier.access_cnt == none_value, 1)],
                                           else_=(models.DataIdentifier.access_cnt + 1))},
                       synchronize_session=False)
    except DatabaseError:
        return False

    return True


@transactional_session
def create_did_sample(input_scope, input_name, output_scope, output_name, account, nbfiles, session=None):
    """
    Create a sample from an input collection.

    :param input_scope: The scope of the input DID.
    :param input_name: The name of the input DID.
    :param output_scope: The scope of the output dataset.
    :param output_name: The name of the output dataset.
    :param account: The account.
    :param nbfiles: The number of files to register in the output dataset.
    :param session: The database session in use.
    """
    files = [did for did in list_files(scope=input_scope, name=input_name, long=False, session=session)]
    random.shuffle(files)
    output_files = files[:int(nbfiles)]
    add_did(scope=output_scope, name=output_name, type=DIDType.DATASET, account=account, statuses={}, meta=[], rules=[], lifetime=None, dids=[], rse_id=None, session=session)
    attach_dids(scope=output_scope, name=output_name, dids=output_files, account=account, rse_id=None, session=session)


@transactional_session
def __resolve_bytes_length_events_did(scope, name, session):
    """
    Resolve bytes, length and events of a did

    :param scope:   The scope of the DID.
    :param name:    The name of the DID.
    :param session: The database session in use.
    """

    try:
        did = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (scope, name))

    bytes, length, events = 0, 0, 0
    if did.did_type == DIDType.FILE:
        bytes, length, events = did.bytes, 1, did.events
    elif did.did_type == DIDType.DATASET:
        try:
            length, bytes, events = session.query(func.count(models.DataIdentifierAssociation.scope),
                                                  func.sum(models.DataIdentifierAssociation.bytes),
                                                  func.sum(models.DataIdentifierAssociation.events)).\
                filter_by(scope=scope, name=name).\
                one()
        except NoResultFound:
            length, bytes, events = 0, 0, 0

    elif did.did_type == DIDType.CONTAINER:
        for dataset in list_child_datasets(scope=scope, name=name, session=session):
            try:
                tmp_length, tmp_bytes, tmp_events = session.query(func.count(models.DataIdentifierAssociation.scope),
                                                                  func.sum(models.DataIdentifierAssociation.bytes),
                                                                  func.sum(models.DataIdentifierAssociation.events)).\
                    filter_by(scope=dataset['scope'], name=dataset['name']).\
                    one()
            except NoResultFound:
                tmp_length, tmp_bytes, tmp_events = 0, 0, 0

            bytes += tmp_bytes or 0
            length += tmp_length or 0
            events += tmp_events or 0
    return (bytes, length, events)


@transactional_session
def resurrect(dids, session=None):
    """
    Resurrect data identifiers.

    :param dids: The list of dids to resurrect.
    :param session: The database session in use.
    """
    for did in dids:
        try:
            del_did = session.query(models.DeletedDataIdentifier).\
                with_hint(models.DeletedDataIdentifier,
                          "INDEX(DELETED_DIDS DELETED_DIDS_PK)", 'oracle').\
                filter_by(scope=did['scope'], name=did['name']).\
                one()
        except NoResultFound:
            # Dataset might still exist, but could have an expiration date, if it has, remove it
            rowcount = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == did['scope'],
                                                                   models.DataIdentifier.name == did['name'],
                                                                   models.DataIdentifier.expired_at < datetime.utcnow()).\
                update({'expired_at': None}, synchronize_session=False)
            if rowcount:
                continue
            raise exception.DataIdentifierNotFound("Deleted Data identifier '%(scope)s:%(name)s' not found" % did)

        # Check did_type
        # if del_did.did_type  == DIDType.FILE:
        #    raise exception.UnsupportedOperation("File '%(scope)s:%(name)s' cannot be resurrected" % did)

        kargs = del_did.to_dict()
        if kargs['expired_at']:
            kargs['expired_at'] = None
        kargs.pop("_sa_instance_state", None)

        session.query(models.DeletedDataIdentifier).\
            with_hint(models.DeletedDataIdentifier,
                      "INDEX(DELETED_DIDS DELETED_DIDS_PK)", 'oracle').\
            filter_by(scope=did['scope'], name=did['name']).\
            delete()

        models.DataIdentifier(**kargs).\
            save(session=session, flush=False)


@stream_session
def list_archive_content(scope, name, session=None):
    """
    List archive contents.

    :param scope: The archive scope name.
    :param name: The archive data identifier name.
    :param session: The database session in use.
    """
    try:
        query = session.query(models.ConstituentAssociation).\
            with_hint(models.ConstituentAssociation,
                      "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle').\
            filter_by(scope=scope, name=name)

        for tmp_did in query.yield_per(5):
            yield {'scope': tmp_did.child_scope, 'name': tmp_did.child_name,
                   'bytes': tmp_did.bytes, 'adler32': tmp_did.adler32, 'md5': tmp_did.md5}
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@transactional_session
def add_did_to_followed(scope, name, account, session=None):
    """
    Mark a did as followed by the given account

    :param scope: The scope name.
    :param name: The data identifier name.
    :param account: The account owner.
    :param session: The database session in use.
    """
    return add_dids_to_followed(dids=[{'scope': scope, 'name': name}],
                                account=account, session=session)


@transactional_session
def add_dids_to_followed(dids, account, session=None):
    """
    Bulk mark datasets as followed

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    try:
        for did in dids:
            # Get the did details corresponding to the scope and name passed.
            did = session.query(models.DataIdentifier).filter_by(scope=did['scope'], name=did['name']).one()
            # Add the queried to the followed table.
            new_did_followed = models.DidsFollowed(scope=did.scope, name=did.name, account=account,
                                                   did_type=did.did_type)

            new_did_followed.save(session=session, flush=False)

        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@stream_session
def get_users_following_did(scope, name, session=None):
    """
    Return list of users following a did

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        query = session.query(models.DidsFollowed).filter_by(scope=scope, name=name).all()

        for user in query:
            # Return a dictionary of users to be rendered as json.
            yield {'user': user.account}

    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (scope, name))


@transactional_session
def remove_did_from_followed(scope, name, account, session=None):
    """
    Mark a did as not followed

    :param scope: The scope name.
    :param name: The data identifier name.
    :param account: The account owner.
    :param session: The database session in use.
    """
    return remove_dids_from_followed(dids=[{'scope': scope, 'name': name}],
                                     account=account, session=session)


@transactional_session
def remove_dids_from_followed(dids, account, session=None):
    """
    Bulk mark datasets as not followed

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    try:
        for did in dids:
            session.query(models.DidsFollowed).\
                filter_by(scope=did['scope'], name=did['name'], account=account).\
                delete(synchronize_session=False)
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (did['scope'], did['name']))


@transactional_session
def trigger_event(scope, name, event_type, payload, session=None):
    """
    Records changes occuring in the did to the FollowEvents table

    :param scope: The scope name.
    :param name: The data identifier name.
    :param event_type: The type of event affecting the did.
    :param payload: Any message to be stored along with the event.
    :param session: The database session in use.
    """
    try:
        dids = session.query(models.DidsFollowed).filter_by(scope=scope, name=name).all()

        for did in dids:
            # Create a new event using teh specified parameters.
            new_event = models.FollowEvents(scope=scope, name=name, account=did.account,
                                            did_type=did.did_type, event_type=event_type, payload=payload)
            new_event.save(session=session, flush=False)

        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)


@read_session
def create_reports(total_workers, worker_number, session=None):
    """
    Create a summary report of the events affecting a dataset, for its followers.

    :param session: The database session in use.
    """
    # Query the FollowEvents table
    query = session.query(models.FollowEvents)

    # Use hearbeat mechanism to select a chunck of events based on the hashed account
    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='account')

    try:
        events = query.order_by(models.FollowEvents.created_at).all()
        # If events exist for an account then create a report.
        if events:
            body = '''
                Hello,
                This is an auto-generated report of the events that have affected the datasets you follow.

                '''
            account = None
            for i, event in enumerate(events):
                # Add each event to the message body.
                body += "{}. Dataset: {} Event: {}\n".format(i + 1, event.name, event.event_type)
                if event.payload:
                    body += "Message: {}\n".format(event.payload)
                body += "\n"
                account = event.account
                # Clean up the event after creating the report
                session.query(models.FollowEvents).\
                    filter_by(scope=event.scope, name=event.name, account=event.account).\
                    delete(synchronize_session=False)

            body += "Thank You."
            # Get the email associated with the account.
            email = session.query(models.Account.email).filter_by(account=account)
            add_message('email', {'to': email,
                                  'subject': 'Report of affected dataset(s)',
                                  'body': body})

    except NoResultFound:
        raise exception.AccountNotFound("No email found for given account.")


@transactional_session
def insert_content_history(content_clause, did_created_at, session=None):
    """
    Insert into content history a list of did

    :param content_clause: Content clause of the files to archive
    :param did_created_at: Creation date of the did
    :param session: The database session in use.
    """
    new_did_created_at = did_created_at
    query = session.query(models.DataIdentifierAssociation.scope,
                          models.DataIdentifierAssociation.name,
                          models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.did_type,
                          models.DataIdentifierAssociation.child_type,
                          models.DataIdentifierAssociation.bytes,
                          models.DataIdentifierAssociation.adler32,
                          models.DataIdentifierAssociation.md5,
                          models.DataIdentifierAssociation.guid,
                          models.DataIdentifierAssociation.events,
                          models.DataIdentifierAssociation.rule_evaluation,
                          models.DataIdentifierAssociation.created_at,
                          models.DataIdentifierAssociation.updated_at).\
        filter(or_(*content_clause))

    for cont in query.all():
        if not did_created_at:
            new_did_created_at = cont.created_at
        models.DataIdentifierAssociationHistory(
            scope=cont.scope,
            name=cont.name,
            child_scope=cont.child_scope,
            child_name=cont.child_name,
            did_type=cont.did_type,
            child_type=cont.child_type,
            bytes=cont.bytes,
            adler32=cont.adler32,
            md5=cont.md5,
            guid=cont.guid,
            events=cont.events,
            rule_evaluation=cont.rule_evaluation,
            updated_at=cont.updated_at,
            created_at=cont.created_at,
            did_created_at=new_did_created_at,
            deleted_at=datetime.utcnow()
        ).save(session=session, flush=False)


@transactional_session
def insert_deleted_dids(did_clause, session=None):
    """
    Insert into deleted_dids a list of did

    :param did_clause: DID clause of the files to archive
    :param session: The database session in use.
    """
    query = session.query(models.DataIdentifier.scope,
                          models.DataIdentifier.name,
                          models.DataIdentifier.account,
                          models.DataIdentifier.did_type,
                          models.DataIdentifier.is_open,
                          models.DataIdentifier.monotonic,
                          models.DataIdentifier.hidden,
                          models.DataIdentifier.obsolete,
                          models.DataIdentifier.complete,
                          models.DataIdentifier.is_new,
                          models.DataIdentifier.availability,
                          models.DataIdentifier.suppressed,
                          models.DataIdentifier.bytes,
                          models.DataIdentifier.length,
                          models.DataIdentifier.md5,
                          models.DataIdentifier.adler32,
                          models.DataIdentifier.expired_at,
                          models.DataIdentifier.purge_replicas,
                          models.DataIdentifier.deleted_at,
                          models.DataIdentifier.events,
                          models.DataIdentifier.guid,
                          models.DataIdentifier.project,
                          models.DataIdentifier.datatype,
                          models.DataIdentifier.run_number,
                          models.DataIdentifier.stream_name,
                          models.DataIdentifier.prod_step,
                          models.DataIdentifier.version,
                          models.DataIdentifier.campaign,
                          models.DataIdentifier.task_id,
                          models.DataIdentifier.panda_id,
                          models.DataIdentifier.lumiblocknr,
                          models.DataIdentifier.provenance,
                          models.DataIdentifier.phys_group,
                          models.DataIdentifier.transient,
                          models.DataIdentifier.accessed_at,
                          models.DataIdentifier.closed_at,
                          models.DataIdentifier.eol_at,
                          models.DataIdentifier.is_archive,
                          models.DataIdentifier.constituent,
                          models.DataIdentifier.access_cnt).\
        filter(or_(*did_clause))

    for did in query.all():
        models.DeletedDataIdentifier(
            scope=did.scope,
            name=did.name,
            account=did.account,
            did_type=did.did_type,
            is_open=did.is_open,
            monotonic=did.monotonic,
            hidden=did.hidden,
            obsolete=did.obsolete,
            complete=did.complete,
            is_new=did.is_new,
            availability=did.availability,
            suppressed=did.suppressed,
            bytes=did.bytes,
            length=did.length,
            md5=did.md5,
            adler32=did.adler32,
            expired_at=did.expired_at,
            purge_replicas=did.purge_replicas,
            deleted_at=datetime.utcnow(),
            events=did.events,
            guid=did.guid,
            project=did.project,
            datatype=did.datatype,
            run_number=did.run_number,
            stream_name=did.stream_name,
            prod_step=did.prod_step,
            version=did.version,
            campaign=did.campaign,
            task_id=did.task_id,
            panda_id=did.panda_id,
            lumiblocknr=did.lumiblocknr,
            provenance=did.provenance,
            phys_group=did.phys_group,
            transient=did.transient,
            accessed_at=did.accessed_at,
            closed_at=did.closed_at,
            eol_at=did.eol_at,
            is_archive=did.is_archive,
            constituent=did.constituent
        ).save(session=session, flush=False)
