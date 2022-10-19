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

import logging
import operator
import random
from datetime import datetime, timedelta
from enum import Enum
from hashlib import md5
from re import match
from typing import TYPE_CHECKING

from sqlalchemy import and_, or_, exists, update, delete, insert
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import not_, func
from sqlalchemy.sql.expression import bindparam, case, select, true, false, null

import rucio.core.replica  # import add_replicas
import rucio.core.rule
from rucio.common import exception
from rucio.common.config import config_get_bool
from rucio.common.utils import is_archive, chunks
from rucio.core import did_meta_plugins, config as config_core
from rucio.core.message import add_message
from rucio.core.monitor import Timer, record_counter
from rucio.core.naming_convention import validate_name
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import DIDType, DIDReEvaluation, DIDAvailability, RuleState, BadFilesStatus
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.db.sqla.util import temp_table_mngr

if TYPE_CHECKING:
    from typing import Any, Dict, Tuple, Optional, Sequence, Callable
    from sqlalchemy.orm import Session
    from sqlalchemy.schema import Table
    from rucio.common.types import InternalAccount, InternalScope

    LoggerFunction = Callable[..., Any]


@read_session
def list_expired_dids(
        worker_number: int = None,
        total_workers: int = None,
        limit: int = None,
        session: "Optional[Session]" = None
):
    """
    List expired data identifiers.

    :param limit: limit number.
    :param session: The database session in use.
    """

    sub_query = exists(
    ).where(
        models.ReplicationRule.scope == models.DataIdentifier.scope,
        models.ReplicationRule.name == models.DataIdentifier.name,
        models.ReplicationRule.locked == true(),
    )
    list_stmt = select(
        models.DataIdentifier.scope,
        models.DataIdentifier.name,
        models.DataIdentifier.did_type,
        models.DataIdentifier.created_at,
        models.DataIdentifier.purge_replicas
    ).where(
        models.DataIdentifier.expired_at < datetime.utcnow(),
        not_(sub_query),
    ).order_by(
        models.DataIdentifier.expired_at
    ).with_hint(
        models.DataIdentifier, "index(DIDS DIDS_EXPIRED_AT_IDX)", 'oracle'
    )

    if session.bind.dialect.name in ['oracle', 'mysql', 'postgresql']:
        list_stmt = filter_thread_work(session=session, query=list_stmt, total_threads=total_workers, thread_id=worker_number, hash_variable='name')
    elif session.bind.dialect.name == 'sqlite' and worker_number and total_workers and total_workers > 0:
        row_count = 0
        dids = list()
        for scope, name, did_type, created_at, purge_replicas in session.execute(list_stmt).yield_per(10):
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
        list_stmt = list_stmt.limit(limit)

    return [{'scope': scope, 'name': name, 'did_type': did_type, 'created_at': created_at,
             'purge_replicas': purge_replicas} for scope, name, did_type, created_at, purge_replicas in session.execute(list_stmt)]


@transactional_session
def add_did(
        scope: "InternalScope",
        name: str,
        did_type: "DIDType",
        account: "InternalAccount",
        statuses: "Optional[Dict[str, Any]]" = None,
        meta: "Optional[Dict[str, Any]]" = None,
        rules: "Optional[Sequence[str]]" = None,
        lifetime: "Optional[int]" = None,
        dids: "Optional[Sequence[Dict[str, Any]]]" = None,
        rse_id: "Optional[str]" = None,
        session: "Optional[Session]" = None,
):
    """
    Add data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param did_type: The data identifier type.
    :param account: The account owner.
    :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
    :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
    :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param lifetime: DID's lifetime (in seconds).
    :param dids: The content.
    :param rse_id: The RSE id when registering replicas.
    :param session: The database session in use.
    """
    return add_dids(dids=[{'scope': scope, 'name': name, 'type': did_type,
                           'statuses': statuses or {}, 'meta': meta or {},
                           'rules': rules, 'lifetime': lifetime,
                           'dids': dids, 'rse_id': rse_id}],
                    account=account, session=session)


@transactional_session
def add_dids(
        dids: "Sequence[Dict[str, Any]]",
        account: "InternalAccount",
        session: "Optional[Session]" = None,
):
    """
    Bulk add data identifiers.

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    try:

        for did in dids:
            try:

                if isinstance(did['type'], str):
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


@transactional_session
def attach_dids(
        scope: "InternalScope",
        name: str,
        dids: "Sequence[Dict[str, Any]]",
        account: "InternalAccount",
        rse_id: "Optional[str]" = None,
        session: "Optional[Session]" = None,
):
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
def attach_dids_to_dids(
        attachments: "Dict[str, Any]",
        account: "InternalAccount",
        ignore_duplicate: bool = False,
        session: "Optional[Session]" = None,
):
    """
    Append content to dids.

    :param attachments: The contents.
    :param account: The account.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    use_temp_tables = config_get_bool('core', 'use_temp_tables', default=False, session=session)
    if use_temp_tables:
        return _attach_dids_to_dids(attachments=attachments, account=account, ignore_duplicate=ignore_duplicate, session=session)
    else:
        return _attach_dids_to_dids_without_temp_tables(attachments=attachments, account=account, ignore_duplicate=ignore_duplicate, session=session)


@transactional_session
def _attach_dids_to_dids(
        attachments: "Dict[str, Any]",
        account: "InternalAccount",
        ignore_duplicate: bool = False,
        session: "Optional[Session]" = None,
):
    """
    Append content to dids.

    :param attachments: The contents.
    :param account: The account.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    children_temp_table = temp_table_mngr(session).create_scope_name_table()
    parent_dids = list()
    first_iteration = True
    for attachment in attachments:
        try:
            children = {(a['scope'], a['name']): a for a in attachment['dids']}
            cont = []
            stmt = select(
                models.DataIdentifier
            ).where(
                models.DataIdentifier.scope == attachment['scope'],
                models.DataIdentifier.name == attachment['name']
            ).with_hint(
                models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
            )
            parent_did = session.execute(stmt).scalar_one()
            if not first_iteration:
                session.query(children_temp_table).delete()
            session.bulk_insert_mappings(children_temp_table, [{'scope': file['scope'], 'name': file['name']} for file in attachment['dids']])

            if parent_did.did_type == DIDType.FILE:
                # check if parent file has the archive extension
                if is_archive(attachment['name']):
                    __add_files_to_archive(parent_did=parent_did,
                                           files_temp_table=children_temp_table,
                                           files=children,
                                           account=account,
                                           ignore_duplicate=ignore_duplicate,
                                           session=session)
                    return
                raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is a file" % attachment)

            elif not parent_did.is_open:
                raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is closed" % attachment)

            elif parent_did.did_type == DIDType.DATASET:
                cont = __add_files_to_dataset(parent_did=parent_did,
                                              files_temp_table=children_temp_table,
                                              files=children,
                                              account=account,
                                              ignore_duplicate=ignore_duplicate,
                                              rse_id=attachment.get('rse_id'),
                                              session=session)

            elif parent_did.did_type == DIDType.CONTAINER:
                __add_collections_to_container(parent_did=parent_did,
                                               collections_temp_table=children_temp_table,
                                               collections=children,
                                               account=account,
                                               session=session)

            if cont:
                # cont contains the parent of the files and is only filled if the files does not exist yet
                parent_dids.append({'scope': parent_did.scope,
                                    'name': parent_did.name,
                                    'rule_evaluation_action': DIDReEvaluation.ATTACH})
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (attachment['scope'], attachment['name']))
        first_iteration = False

    # Remove all duplicated dictionnaries from the list
    # (convert the list of dictionaries into a list of tuple, then to a set of tuple
    # to remove duplicates, then back to a list of unique dictionaries)
    parent_dids = [dict(tup) for tup in set(tuple(dictionary.items()) for dictionary in parent_dids)]
    session.bulk_insert_mappings(models.UpdatedDID, parent_dids)


def __add_files_to_archive(parent_did, files_temp_table, files, account, ignore_duplicate=False, session=None):
    """
    Add files to archive.

    :param parent_did: the DataIdentifier object of the parent did
    :param files: archive content.
    :param account: The account owner.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    stmt = select(
        files_temp_table.scope,
        files_temp_table.name,
        models.DataIdentifier.scope.label('did_scope'),
        models.DataIdentifier.bytes,
        models.DataIdentifier.guid,
        models.DataIdentifier.events,
        models.DataIdentifier.availability,
        models.DataIdentifier.adler32,
        models.DataIdentifier.md5,
        models.DataIdentifier.is_archive,
        models.DataIdentifier.constituent,
        models.DataIdentifier.did_type,
    ).outerjoin_from(
        files_temp_table,
        models.DataIdentifier,
        and_(
            models.DataIdentifier.scope == files_temp_table.scope,
            models.DataIdentifier.name == files_temp_table.name,
        ),
    )
    if ignore_duplicate:
        stmt = stmt.add_columns(
            models.ConstituentAssociation.scope.label('archive_contents_scope'),
        ).outerjoin_from(
            files_temp_table,
            models.ConstituentAssociation,
            and_(
                models.ConstituentAssociation.scope == parent_did.scope,
                models.ConstituentAssociation.name == parent_did.name,
                models.ConstituentAssociation.child_scope == files_temp_table.scope,
                models.ConstituentAssociation.child_name == files_temp_table.name,
            ),
        )

    dids_to_add = {}
    must_set_constituent = False
    archive_contents_to_add = {}
    for row in session.execute(stmt):
        file = files[row.scope, row.name]

        if ignore_duplicate and row.archive_contents_scope is not None:
            continue

        if (row.scope, row.name) in archive_contents_to_add:
            # Ignore duplicate input
            continue

        if row.did_scope is None:
            new_did = {}
            new_did.update((k, v) for k, v in file.items() if k != 'meta')
            for key in file.get('meta', {}):
                new_did[key] = file['meta'][key]
            new_did['constituent'] = True
            new_did['did_type'] = DIDType.FILE
            new_did['account'] = account
            dids_to_add[row.scope, row.name] = new_did

            new_content = {
                'child_scope': file['scope'],
                'child_name': file['name'],
                'scope': parent_did.scope,
                'name': parent_did.name,
                'bytes': file['bytes'],
                'adler32': file.get('adler32'),
                'md5': file.get('md5'),
                'guid': file.get('guid'),
                'length': file.get('events')
            }
        else:
            if row.did_type != DIDType.FILE:
                raise exception.UnsupportedOperation('Data identifier %s:%s of type %s cannot be added to an archive ' % (row.scope, row.name, row.did_type))

            if not row.constituent:
                must_set_constituent = True

            new_content = {
                'child_scope': row.scope,
                'child_name': row.name,
                'scope': parent_did.scope,
                'name': parent_did.name,
                'bytes': row.bytes,
                'adler32': row.adler32,
                'md5': row.md5,
                'guid': row.guid,
                'length': row.events
            }

        archive_contents_to_add[row.scope, row.name] = new_content

    # insert into archive_contents
    try:
        dids_to_add and session.bulk_insert_mappings(models.DataIdentifier, dids_to_add.values())
        archive_contents_to_add and session.bulk_insert_mappings(models.ConstituentAssociation, archive_contents_to_add.values())
        if must_set_constituent:
            stmt = update(
                models.DataIdentifier
            ).where(
                exists(
                    select([1])
                ).where(
                    models.DataIdentifier.scope == files_temp_table.scope,
                    models.DataIdentifier.name == files_temp_table.name
                )
            ).where(
                or_(models.DataIdentifier.constituent.is_(None),
                    models.DataIdentifier.constituent == false())
            ).execution_options(
                synchronize_session=False
            ).values(
                constituent=True
            )
            session.execute(stmt)
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)

    if not parent_did.is_archive:
        # mark tha archive file as is_archive
        parent_did.is_archive = True

        # mark parent datasets as is_archive = True
        stmt = update(
            models.DataIdentifier
        ).where(
            exists(
                select([1]).prefix_with("/*+ INDEX(CONTENTS CONTENTS_CHILD_SCOPE_NAME_IDX) */", dialect="oracle")
            ).where(
                models.DataIdentifierAssociation.child_scope == parent_did.scope,
                models.DataIdentifierAssociation.child_name == parent_did.name,
                models.DataIdentifierAssociation.scope == models.DataIdentifier.scope,
                models.DataIdentifierAssociation.name == models.DataIdentifier.name
            )
        ).where(
            or_(models.DataIdentifier.is_archive.is_(None),
                models.DataIdentifier.is_archive == false())
        ).execution_options(
            synchronize_session=False
        ).values(
            is_archive=True
        )
        session.execute(stmt)


@transactional_session
def __add_files_to_dataset(parent_did, files_temp_table, files, account, rse_id, ignore_duplicate=False, session=None):
    """
    Add files to dataset.

    :param parent_did:         the DataIdentifier object of the parent did
    :param files_temp_table:   Temporary table containing the scope and name of files to add.
    :param account:            The account owner.
    :param rse_id:             The RSE id for the replicas.
    :param ignore_duplicate:   If True, ignore duplicate entries.
    :param session:            The database session in use.
    :returns:                  List of files attached (excluding the ones that were already attached to the dataset).
    """
    # Get metadata from dataset
    try:
        dataset_meta = validate_name(scope=parent_did.scope, name=parent_did.name, did_type='D')
    except Exception:
        dataset_meta = None

    if rse_id:
        # Tier-0 uses this old work-around to register replicas on the RSE
        # in the same call as attaching them to a dataset
        rucio.core.replica.add_replicas(rse_id=rse_id, files=files.values(), dataset_meta=dataset_meta,
                                        account=account, session=session)

    stmt = select(
        files_temp_table.scope,
        files_temp_table.name,
        models.DataIdentifier.scope.label('did_scope'),
        models.DataIdentifier.bytes,
        models.DataIdentifier.guid,
        models.DataIdentifier.events,
        models.DataIdentifier.availability,
        models.DataIdentifier.adler32,
        models.DataIdentifier.md5,
        models.DataIdentifier.is_archive,
        models.DataIdentifier.did_type,
    ).outerjoin_from(
        files_temp_table,
        models.DataIdentifier,
        and_(
            models.DataIdentifier.scope == files_temp_table.scope,
            models.DataIdentifier.name == files_temp_table.name,
        ),
    )
    if ignore_duplicate:
        stmt = stmt.add_columns(
            models.DataIdentifierAssociation.scope.label('contents_scope'),
        ).outerjoin_from(
            files_temp_table,
            models.DataIdentifierAssociation,
            and_(
                models.DataIdentifierAssociation.scope == parent_did.scope,
                models.DataIdentifierAssociation.name == parent_did.name,
                models.DataIdentifierAssociation.child_scope == files_temp_table.scope,
                models.DataIdentifierAssociation.child_name == files_temp_table.name,
            ),
        )

    files_to_add = {}
    for row in session.execute(stmt):
        file = files[row.scope, row.name]

        if row.did_scope is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % row)

        if row.availability == DIDAvailability.LOST:
            raise exception.UnsupportedOperation('File %s:%s is LOST and cannot be attached' % (row.scope, row.name))

        if row.did_type != DIDType.FILE:
            raise exception.UnsupportedOperation('Data identifier %s:%s of type %s cannot be added to a dataset ' % (row.scope, row.name, row.did_type))

        # Check meta-data, if provided
        for key in ['bytes', 'adler32', 'md5']:
            if key in file and str(file[key]) != str(row[key]):
                raise exception.FileConsistencyMismatch(key + " mismatch for '%(scope)s:%(name)s': " % row + str(file.get(key)) + '!=' + str(row[key]))

        if ignore_duplicate and row.contents_scope is not None:
            continue

        if (row.scope, row.name) in files_to_add:
            # Ignore duplicate input files
            continue

        if row.is_archive and not parent_did.is_archive:
            parent_did.is_archive = True

        files_to_add[(row.scope, row.name)] = {
            'scope': parent_did.scope,
            'name': parent_did.name,
            'child_scope': row['scope'],
            'child_name': row['name'],
            'bytes': row['bytes'],
            'adler32': row['adler32'],
            'md5': row['md5'],
            'guid': row['guid'],
            'events': row['events'],
            'did_type': DIDType.DATASET,
            'child_type': DIDType.FILE,
            'rule_evaluation': True,
        }

    try:
        files_to_add and session.bulk_insert_mappings(models.DataIdentifierAssociation, files_to_add.values())
        session.flush()
        return files_to_add
    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-02291: integrity constraint .*CONTENTS_CHILD_ID_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', error.args[0]) \
                or match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]) \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint.*', error.args[0]):
            raise exception.DataIdentifierNotFound("Data identifier not found")
        elif match('.*IntegrityError.*ORA-00001: unique constraint .*CONTENTS_PK.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*UNIQUE constraint failed: contents.scope, contents.name, contents.child_scope, contents.child_name.*', error.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry .*for key.*PRIMARY.*', error.args[0]) \
                or match('.*duplicate entry.*key.*PRIMARY.*', error.args[0]) \
                or match('.*IntegrityError.*columns? .*not unique.*', error.args[0]):
            raise exception.FileAlreadyExists(error.args)
        else:
            raise exception.RucioException(error.args)


@transactional_session
def __add_collections_to_container(parent_did, collections_temp_table, collections, account, session):
    """
    Add collections (datasets or containers) to container.

    :param parent_did: the DataIdentifier object of the parent did
    :param collections: .
    :param account: The account owner.
    :param session: The database session in use.
    """

    if (parent_did.scope, parent_did.name) in collections:
        raise exception.UnsupportedOperation('Self-append is not valid!')

    stmt = select(
        collections_temp_table.scope,
        collections_temp_table.name,
        models.DataIdentifier.scope.label('did_scope'),
        models.DataIdentifier.did_type
    ).outerjoin_from(
        collections_temp_table,
        models.DataIdentifier,
        and_(
            models.DataIdentifier.scope == collections_temp_table.scope,
            models.DataIdentifier.name == collections_temp_table.name,
        ),
    )

    container_parents = None
    child_type = None
    for row in session.execute(stmt):

        if row.did_scope is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % row)

        if row.did_type == DIDType.FILE:
            raise exception.UnsupportedOperation("Adding a file (%s:%s) to a container (%s:%s) is forbidden" % (row.scope, row.name, parent_did.scope, parent_did.name))

        if not child_type:
            child_type = row.did_type

        if child_type != row.did_type:
            raise exception.UnsupportedOperation("Mixed collection is not allowed: '%s:%s' is a %s(expected type: %s)" % (row.scope, row.name, row.did_type, child_type))

        if child_type == DIDType.CONTAINER:
            if container_parents is None:
                container_parents = {(parent['scope'], parent['name']) for parent in list_all_parent_dids(scope=parent_did.scope, name=parent_did.name, session=session)}

            if (row.scope, row.name) in container_parents:
                raise exception.UnsupportedOperation('Circular attachment detected. %s:%s is already a parent of %s:%s' % (row.scope, row.name, parent_did.scope, parent_did.name))

    messages = []
    for c in collections.values():
        did_asso = models.DataIdentifierAssociation(
            scope=parent_did.scope,
            name=parent_did.name,
            child_scope=c['scope'],
            child_name=c['name'],
            did_type=DIDType.CONTAINER,
            child_type=child_type,
            rule_evaluation=True
        )
        did_asso.save(session=session, flush=False)
        # Send AMI messages
        if child_type == DIDType.CONTAINER:
            chld_type = 'CONTAINER'
        elif child_type == DIDType.DATASET:
            chld_type = 'DATASET'
        else:
            chld_type = 'UNKNOWN'

        message = {'account': account.external,
                   'scope': parent_did.scope.external,
                   'name': parent_did.name,
                   'childscope': c['scope'].external,
                   'childname': c['name'],
                   'childtype': chld_type}
        if account.vo != 'def':
            message['vo'] = account.vo
        messages.append(message)

    try:
        for message in messages:
            add_message('REGISTER_CNT', message, session=session)
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


def __add_files_to_archive_without_temp_tables(scope, name, files, account, ignore_duplicate=False, session=None):
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
    files_query = select(
        models.DataIdentifier.scope,
        models.DataIdentifier.name,
        models.DataIdentifier.bytes,
        models.DataIdentifier.guid,
        models.DataIdentifier.events,
        models.DataIdentifier.availability,
        models.DataIdentifier.adler32,
        models.DataIdentifier.md5,
    ).where(
        models.DataIdentifier.did_type == DIDType.FILE
    ).with_hint(
        models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
    )

    file_condition = []
    for file in files:
        file_condition.append(and_(models.DataIdentifier.scope == file['scope'],
                                   models.DataIdentifier.name == file['name']))

    existing_content, existing_files = [], {}
    if ignore_duplicate:
        # lookup for existing content
        content_query = select(
            models.ConstituentAssociation.scope,
            models.ConstituentAssociation.name,
            models.ConstituentAssociation.child_scope,
            models.ConstituentAssociation.child_name
        ).with_hint(
            models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle'
        )
        content_condition = []
        for file in files:
            content_condition.append(and_(models.ConstituentAssociation.scope == scope,
                                          models.ConstituentAssociation.name == name,
                                          models.ConstituentAssociation.child_scope == file['scope'],
                                          models.ConstituentAssociation.child_name == file['name']))
        for row in session.execute(content_query.where(or_(*content_condition))):
            existing_content.append(row)

    for row in session.execute(files_query.where(or_(*file_condition))):
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
                stmt = update(
                    models.DataIdentifier
                ).prefix_with(
                    "/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle'
                ).where(
                    models.DataIdentifier.did_type == DIDType.FILE
                ).where(
                    or_(models.DataIdentifier.constituent.is_(None),
                        models.DataIdentifier.constituent == false())
                ).where(
                    or_(*chunk)
                ).values(
                    constituent=True
                )
                session.execute(stmt)
        contents and session.bulk_insert_mappings(models.ConstituentAssociation, contents)
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)

    stmt = select(
        models.DataIdentifier
    ).where(
        models.DataIdentifier.did_type == DIDType.FILE,
        models.DataIdentifier.scope == scope,
        models.DataIdentifier.name == name,
    )
    archive_did = session.execute(stmt).scalar()
    if not archive_did.is_archive:
        # mark tha archive file as is_archive
        archive_did.is_archive = True

        # mark parent datasets as is_archive = True
        stmt = update(
            models.DataIdentifier
        ).where(
            exists(
                select([1]).prefix_with("/*+ INDEX(CONTENTS CONTENTS_CHILD_SCOPE_NAME_IDX) */", dialect="oracle")
            ).where(
                models.DataIdentifierAssociation.child_scope == scope,
                models.DataIdentifierAssociation.child_name == name,
                models.DataIdentifierAssociation.scope == models.DataIdentifier.scope,
                models.DataIdentifierAssociation.name == models.DataIdentifier.name
            )
        ).where(
            or_(models.DataIdentifier.is_archive.is_(None),
                models.DataIdentifier.is_archive == false())
        ).execution_options(
            synchronize_session=False
        ).values(
            is_archive=True
        )
        session.execute(stmt)


@transactional_session
def __add_files_to_dataset_without_temp_tables(scope, name, files, account, rse_id, ignore_duplicate=False, session=None):
    """
    Add files to dataset.

    :param scope:              The scope name.
    :param name:               The data identifier name.
    :param files:              The list of files.
    :param account:            The account owner.
    :param rse_id:             The RSE id for the replicas.
    :param ignore_duplicate:   If True, ignore duplicate entries.
    :param session:            The database session in use.
    :returns:                  List of files attached (excluding the ones that were already attached to the dataset).
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
        content_query = select(
            models.DataIdentifierAssociation.scope,
            models.DataIdentifierAssociation.name,
            models.DataIdentifierAssociation.child_scope,
            models.DataIdentifierAssociation.child_name
        ).with_hint(
            models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle'
        )
        content_condition = []
        for file in files:
            content_condition.append(and_(models.DataIdentifierAssociation.scope == scope,
                                          models.DataIdentifierAssociation.name == name,
                                          models.DataIdentifierAssociation.child_scope == file['scope'],
                                          models.DataIdentifierAssociation.child_name == file['name']))
        for row in session.execute(content_query.where(or_(*content_condition))):
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
    stmt = select(
        models.DataIdentifier
    ).with_hint(
        models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
    ).where(
        or_(*added_archives_condition)
    ).limit(
        1
    )
    if session.execute(stmt).scalar() is not None:
        stmt = update(
            models.DataIdentifier
        ).where(
            models.DataIdentifier.scope == scope,
            models.DataIdentifier.name == name,
        ).where(
            or_(models.DataIdentifier.is_archive.is_(None),
                models.DataIdentifier.is_archive == false())
        ).values(
            is_archive=True
        )
        session.execute(stmt)

    try:
        contents and session.bulk_insert_mappings(models.DataIdentifierAssociation, contents)
        session.flush()
        return contents
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
def __add_collections_to_container_without_temp_tables(scope, name, collections, account, session):
    """
    Add collections (datasets or containers) to container.

    :param scope: The scope name.
    :param name: The container name.
    :param collections: .
    :param account: The account owner.
    :param session: The database session in use.
    """
    container_parents = None
    condition = []
    for cond in collections:

        if (scope == cond['scope']) and (name == cond['name']):
            raise exception.UnsupportedOperation('Self-append is not valid!')

        condition.append(and_(models.DataIdentifier.scope == cond['scope'],
                              models.DataIdentifier.name == cond['name']))

    available_dids = {}
    child_type = None
    stmt = select(
        models.DataIdentifier.scope,
        models.DataIdentifier.name,
        models.DataIdentifier.did_type
    ).with_hint(
        models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
    ).where(
        or_(*condition)
    )
    for row in session.execute(stmt):

        if row.did_type == DIDType.FILE:
            raise exception.UnsupportedOperation("Adding a file (%s:%s) to a container (%s:%s) is forbidden" % (row.scope, row.name, scope, name))

        if not child_type:
            child_type = row.did_type

        available_dids['%s:%s' % (row.scope.internal, row.name)] = row.did_type

        if child_type != row.did_type:
            raise exception.UnsupportedOperation("Mixed collection is not allowed: '%s:%s' is a %s(expected type: %s)" % (row.scope, row.name, row.did_type, child_type))

        if child_type == DIDType.CONTAINER:
            if container_parents is None:
                container_parents = {(parent['scope'], parent['name']) for parent in list_all_parent_dids(scope=scope, name=name, session=session)}

            if (row.scope, row.name) in container_parents:
                raise exception.UnsupportedOperation('Circular attachment detected. %s:%s is already a parent of %s:%s', row.scope, row.name, scope, name)

    messages = []
    for c in collections:
        did_asso = models.DataIdentifierAssociation(
            scope=scope,
            name=name,
            child_scope=c['scope'],
            child_name=c['name'],
            did_type=DIDType.CONTAINER,
            child_type=available_dids.get('%s:%s' % (c['scope'].internal, c['name'])),
            rule_evaluation=True
        )
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
        messages.append(message)

    try:
        for message in messages:
            add_message('REGISTER_CNT', message, session=session)
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
def _attach_dids_to_dids_without_temp_tables(attachments, account, ignore_duplicate=False, session=None):
    """
    Append content to dids.

    :param attachments: The contents.
    :param account: The account.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param session: The database session in use.
    """
    parent_dids = list()
    for attachment in attachments:
        try:
            cont = []
            stmt = select(
                models.DataIdentifier
            ).where(
                models.DataIdentifier.scope == attachment['scope'],
                models.DataIdentifier.name == attachment['name']
            ).with_hint(
                models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
            )
            parent_did = session.execute(stmt).scalar_one()
            update_parent = False

            if parent_did.did_type == DIDType.FILE:
                # check if parent file has the archive extension
                if is_archive(attachment['name']):
                    __add_files_to_archive_without_temp_tables(scope=attachment['scope'],
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
                cont = __add_files_to_dataset_without_temp_tables(scope=attachment['scope'], name=attachment['name'],
                                                                  files=attachment['dids'], account=account,
                                                                  ignore_duplicate=ignore_duplicate,
                                                                  rse_id=attachment.get('rse_id'),
                                                                  session=session)

                update_parent = len(cont) > 0

            elif parent_did.did_type == DIDType.CONTAINER:
                __add_collections_to_container_without_temp_tables(scope=attachment['scope'],
                                                                   name=attachment['name'],
                                                                   collections=attachment['dids'],
                                                                   account=account, session=session)
                update_parent = True

            if update_parent:
                # cont contains the parent of the files and is only filled if the files does not exist yet
                parent_dids.append({'scope': parent_did.scope,
                                    'name': parent_did.name,
                                    'rule_evaluation_action': DIDReEvaluation.ATTACH})
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (attachment['scope'], attachment['name']))

    # Remove all duplicated dictionnaries from the list
    # (convert the list of dictionaries into a list of tuple, then to a set of tuple
    # to remove duplicates, then back to a list of unique dictionaries)
    parent_dids = [dict(tup) for tup in set(tuple(dictionary.items()) for dictionary in parent_dids)]
    session.bulk_insert_mappings(models.UpdatedDID, parent_dids)


@transactional_session
def delete_dids(
        dids: "Sequence[Dict[str, Any]]",
        account: "InternalAccount",
        expire_rules: bool = False,
        session: "Optional[Session]" = None,
        logger: "LoggerFunction" = logging.log,
):
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
    use_temp_tables = config_get_bool('core', 'use_temp_tables', default=False, session=session)
    if use_temp_tables:
        return _delete_dids(dids, account, expire_rules, session, logger)
    else:
        return _delete_dids_wo_temp_tables(dids, account, expire_rules, session, logger)


def _delete_dids(
        dids: "Sequence[Dict[str, Any]]",
        account: "InternalAccount",
        expire_rules: bool = False,
        session: "Optional[Session]" = None,
        logger: "LoggerFunction" = logging.log,
):
    if not dids:
        return

    not_purge_replicas = []

    archive_dids = config_core.get('deletion', 'archive_dids', default=False, session=session)
    archive_content = config_core.get('deletion', 'archive_content', default=False, session=session)

    file_dids = {}
    collection_dids = {}
    all_dids = {}
    for did in dids:
        scope, name = did['scope'], did['name']
        logger(logging.INFO, 'Removing did %(scope)s:%(name)s (%(did_type)s)' % did)
        all_dids[scope, name] = {'scope': scope, 'name': name}
        if did['did_type'] == DIDType.FILE:
            file_dids[scope, name] = {'scope': scope, 'name': name}
        else:
            collection_dids[scope, name] = {'scope': scope, 'name': name}

        # ATLAS LOCALGROUPDISK Archive policy
        if did['did_type'] == DIDType.DATASET and did['scope'].external != 'archive':
            try:
                rucio.core.rule.archive_localgroupdisk_datasets(scope=did['scope'], name=did['name'], session=session)
            except exception.UndefinedPolicy:
                pass

        if did['purge_replicas'] is False:
            not_purge_replicas.append((did['scope'], did['name']))

        if archive_content:
            insert_content_history(filter_=[and_(models.DataIdentifierAssociation.scope == did['scope'],
                                                 models.DataIdentifierAssociation.name == did['name'])],
                                   did_created_at=did.get('created_at'),
                                   session=session)

        # Send message
        message = {'account': account.external,
                   'scope': did['scope'].external,
                   'name': did['name']}
        if did['scope'].vo != 'def':
            message['vo'] = did['scope'].vo

        add_message('ERASE', message, session=session)

    temp_table = temp_table_mngr(session).create_scope_name_table()
    if not file_dids:
        data_in_temp_table = all_dids = collection_dids
    elif not collection_dids:
        data_in_temp_table = all_dids = file_dids
    else:
        data_in_temp_table = all_dids
    session.bulk_insert_mappings(temp_table, data_in_temp_table.values())

    # Delete rules on did
    skip_deletion = False  # Skip deletion in case of expiration of a rule
    with Timer('undertaker.rules'):
        stmt = select(
            models.ReplicationRule.id,
            models.ReplicationRule.scope,
            models.ReplicationRule.name,
            models.ReplicationRule.rse_expression,
            models.ReplicationRule.locks_ok_cnt,
            models.ReplicationRule.locks_replicating_cnt,
            models.ReplicationRule.locks_stuck_cnt
        ).join_from(
            temp_table,
            models.ReplicationRule,
            and_(models.ReplicationRule.scope == temp_table.scope,
                 models.ReplicationRule.name == temp_table.name)
        )
        for (rule_id, scope, name, rse_expression, locks_ok_cnt, locks_replicating_cnt, locks_stuck_cnt) in session.execute(stmt):
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
    with Timer('undertaker.parent_content'):
        stmt = select(
            models.DataIdentifierAssociation
        ).join_from(
            temp_table,
            models.DataIdentifierAssociation,
            and_(models.DataIdentifierAssociation.child_scope == temp_table.scope,
                 models.DataIdentifierAssociation.child_name == temp_table.name)
        )
        for parent_did in session.execute(stmt).scalars():
            existing_parent_dids = True
            detach_dids(scope=parent_did.scope, name=parent_did.name, dids=[{'scope': parent_did.child_scope, 'name': parent_did.child_name}], session=session)

    # Remove generic did metadata
    must_delete_did_meta = True
    if session.bind.dialect.name == 'oracle':
        oracle_version = int(session.connection().connection.version.split('.')[0])
        if oracle_version < 12:
            must_delete_did_meta = False
    if must_delete_did_meta:
        stmt = delete(
            models.DidMeta
        ).where(
            exists(
                select([1])
            ).where(
                models.DidMeta.scope == temp_table.scope,
                models.DidMeta.name == temp_table.name
            )
        ).execution_options(
            synchronize_session=False
        )
        with Timer('undertaker.did_meta'):
            session.execute(stmt)

    # Prepare the common part of the query for updating bad replicas if they exist
    bad_replica_stmt = update(
        models.BadReplicas
    ).where(
        models.BadReplicas.state == BadFilesStatus.BAD
    ).values(
        state=BadFilesStatus.DELETED,
        updated_at=datetime.utcnow(),
    ).execution_options(
        synchronize_session=False
    )

    if file_dids:
        if data_in_temp_table is not file_dids:
            session.execute(delete(temp_table))
            session.bulk_insert_mappings(temp_table, file_dids.values())
            data_in_temp_table = file_dids

        # update bad files passed directly as input
        stmt = bad_replica_stmt.where(
            exists(
                select([1])
            ).where(
                models.BadReplicas.scope == temp_table.scope,
                models.BadReplicas.name == temp_table.name
            )
        )
        session.execute(stmt)

    if collection_dids:
        if data_in_temp_table is not collection_dids:
            session.execute(delete(temp_table))
            session.bulk_insert_mappings(temp_table, collection_dids.values())
            data_in_temp_table = collection_dids

        # Find files of datasets passed as input and put them in a separate temp table
        resolved_files_temp_table = temp_table_mngr(session).create_scope_name_table()
        stmt = insert(
            resolved_files_temp_table,
        ).from_select(
            ['scope', 'name'],
            select(
                models.DataIdentifierAssociation.child_scope,
                models.DataIdentifierAssociation.child_name,
            ).join_from(
                temp_table,
                models.DataIdentifierAssociation,
                and_(models.DataIdentifierAssociation.scope == temp_table.scope,
                     models.DataIdentifierAssociation.name == temp_table.name)
            ).where(
                models.DataIdentifierAssociation.child_type == DIDType.FILE
            ).distinct(
            )
        )
        session.execute(stmt)

        # update bad files from datasets
        stmt = bad_replica_stmt.where(
            exists(
                select([1])
            ).where(
                models.BadReplicas.scope == resolved_files_temp_table.scope,
                models.BadReplicas.name == resolved_files_temp_table.name
            )
        )
        session.execute(stmt)

        # Set Epoch tombstone for the files replicas inside the did
        if config_core.get('undertaker', 'purge_all_replicas', default=False, session=session):
            with Timer('undertaker.file_content'):
                stmt = update(
                    models.RSEFileAssociation
                ).where(
                    exists(
                        select([1])
                    ).where(
                        models.RSEFileAssociation.scope == resolved_files_temp_table.scope,
                        models.RSEFileAssociation.name == resolved_files_temp_table.name
                    )
                ).where(
                    models.RSEFileAssociation.lock_cnt == 0,
                    models.RSEFileAssociation.tombstone != null()
                ).execution_options(
                    synchronize_session=False
                ).values(
                    tombstone=datetime(1970, 1, 1)
                )
                session.execute(stmt)

        # Remove content
        with Timer('undertaker.content'):
            stmt = delete(
                models.DataIdentifierAssociation
            ).where(
                exists(
                    select([1])
                ).where(
                    models.DataIdentifierAssociation.scope == temp_table.scope,
                    models.DataIdentifierAssociation.name == temp_table.name
                )
            ).execution_options(
                synchronize_session=False
            )
            rowcount = session.execute(stmt).rowcount
        record_counter(name='undertaker.content.rowcount', delta=rowcount)

        # Remove CollectionReplica
        with Timer('undertaker.collection_replicas'):
            stmt = delete(
                models.CollectionReplica
            ).where(
                exists(
                    select([1])
                ).where(
                    models.CollectionReplica.scope == temp_table.scope,
                    models.CollectionReplica.name == temp_table.name
                )
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    # remove data identifier
    if existing_parent_dids:
        # Exit method early to give Judge time to remove locks (Otherwise, due to foreign keys, did removal does not work
        logger(logging.DEBUG, 'Leaving delete_dids early for Judge-Evaluator checks')
        return

    if collection_dids:
        if data_in_temp_table is not collection_dids:
            session.execute(delete(temp_table))
            session.bulk_insert_mappings(temp_table, collection_dids.values())
            data_in_temp_table = collection_dids

        with Timer('undertaker.dids_followed'):
            stmt = delete(
                models.DidsFollowed
            ).where(
                exists(
                    select([1])
                ).where(
                    models.DidsFollowed.scope == temp_table.scope,
                    models.DidsFollowed.name == temp_table.name
                )
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

        with Timer('undertaker.dids'):
            dids_to_delete_filter = exists(
                select([1])
            ).where(
                models.DataIdentifier.scope == temp_table.scope,
                models.DataIdentifier.name == temp_table.name,
                models.DataIdentifier.did_type.in_([DIDType.CONTAINER, DIDType.DATASET])
            )

            if archive_dids:
                insert_deleted_dids(filter_=dids_to_delete_filter, session=session)

            stmt = delete(
                models.DataIdentifier
            ).where(
                dids_to_delete_filter,
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    if file_dids:
        if data_in_temp_table is not file_dids:
            session.execute(delete(temp_table))
            session.bulk_insert_mappings(temp_table, file_dids.values())
            data_in_temp_table = file_dids
        stmt = update(
            models.DataIdentifier
        ).where(
            exists(
                select([1])
            ).where(
                models.DataIdentifier.scope == temp_table.scope,
                models.DataIdentifier.name == temp_table.name
            )
        ).where(
            models.DataIdentifier.did_type == DIDType.FILE
        ).execution_options(
            synchronize_session=False
        ).values(
            expired_at=None
        )
        session.execute(stmt)


def _delete_dids_wo_temp_tables(
        dids: "Sequence[Dict[str, Any]]",
        account: "InternalAccount",
        expire_rules: bool = False,
        session: "Optional[Session]" = None,
        logger: "LoggerFunction" = logging.log,
):
    rule_id_clause, content_clause = [], []
    parent_content_clause, did_clause = [], []
    collection_replica_clause, file_clause = [], []
    not_purge_replicas = []
    did_followed_clause = []
    metadata_to_delete = []
    file_content_clause = []
    bad_replicas_clause = []
    dataset_clause = []

    archive_dids = config_core.get('deletion', 'archive_dids', default=False, session=session)

    for did in dids:
        logger(logging.INFO, 'Removing did %(scope)s:%(name)s (%(did_type)s)' % did)
        if did['did_type'] == DIDType.FILE:
            file_clause.append(and_(models.DataIdentifier.scope == did['scope'], models.DataIdentifier.name == did['name']))
            bad_replicas_clause.append(and_(models.BadReplicas.scope == did['scope'], models.BadReplicas.name == did['name']))
        else:
            did_clause.append(and_(models.DataIdentifier.scope == did['scope'], models.DataIdentifier.name == did['name']))
            content_clause.append(and_(models.DataIdentifierAssociation.scope == did['scope'], models.DataIdentifierAssociation.name == did['name']))
            file_content_clause.append(and_(models.DataIdentifierAssociation.scope == did['scope'], models.DataIdentifierAssociation.name == did['name'], models.DataIdentifierAssociation.child_type == DIDType.FILE))
            collection_replica_clause.append(and_(models.CollectionReplica.scope == did['scope'],
                                                  models.CollectionReplica.name == did['name']))
            did_followed_clause.append(and_(models.DidsFollowed.scope == did['scope'], models.DidsFollowed.name == did['name']))
            if did['did_type'] == DIDType.DATASET:
                dataset_clause.append(and_(models.DataIdentifierAssociation.scope == did['scope'], models.DataIdentifierAssociation.name == did['name']))

        # ATLAS LOCALGROUPDISK Archive policy
        if did['did_type'] == DIDType.DATASET and did['scope'].external != 'archive':
            try:
                rucio.core.rule.archive_localgroupdisk_datasets(scope=did['scope'], name=did['name'], session=session)
            except exception.UndefinedPolicy:
                pass

        if did['purge_replicas'] is False:
            not_purge_replicas.append((did['scope'], did['name']))

            # Archive content
        archive_content = config_core.get('deletion', 'archive_content', default=False, session=session)
        if archive_content:
            insert_content_history(filter_=[and_(models.DataIdentifierAssociation.scope == did['scope'],
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
        with Timer('undertaker.rules'):
            stmt = select(
                models.ReplicationRule.id,
                models.ReplicationRule.scope,
                models.ReplicationRule.name,
                models.ReplicationRule.rse_expression,
                models.ReplicationRule.locks_ok_cnt,
                models.ReplicationRule.locks_replicating_cnt,
                models.ReplicationRule.locks_stuck_cnt
            ).where(
                or_(*rule_id_clause)
            )
            for (rule_id, scope, name, rse_expression, locks_ok_cnt, locks_replicating_cnt, locks_stuck_cnt) in session.execute(stmt):
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
        with Timer('undertaker.parent_content'):
            stmt = select(
                models.DataIdentifierAssociation
            ).where(
                or_(*parent_content_clause)
            )
            for parent_did in session.execute(stmt).scalars():
                existing_parent_dids = True
                detach_dids(scope=parent_did.scope, name=parent_did.name, dids=[{'scope': parent_did.child_scope, 'name': parent_did.child_name}], session=session)

    # Set Epoch tombstone for the files replicas inside the did
    if config_core.get('undertaker', 'purge_all_replicas', default=False, session=session) and file_content_clause:
        with Timer('undertaker.file_content'):
            stmt = select(
                models.DataIdentifierAssociation.child_scope,
                models.DataIdentifierAssociation.child_name,
            ).where(
                or_(*file_content_clause)
            )
            file_replicas_clause = [and_(models.RSEFileAssociation.scope == child_scope,
                                         models.RSEFileAssociation.name == child_name)
                                    for child_scope, child_name in session.execute(stmt)]
            none_value = None  # Hack to get pep8 happy
            for chunk in chunks(file_replicas_clause, 100):
                stmt = update(
                    models.RSEFileAssociation
                ).prefix_with(
                    "/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle'
                ).where(
                    or_(*chunk)
                ).where(
                    models.RSEFileAssociation.lock_cnt == 0,
                    models.RSEFileAssociation.tombstone != none_value,
                ).execution_options(
                    synchronize_session=False
                ).values(
                    tombstone=datetime(1970, 1, 1)
                )
                session.execute(stmt)

    # Update bad_replicas if exist
    if bad_replicas_clause:
        for chunk in chunks(bad_replicas_clause, 50):
            stmt = update(
                models.BadReplicas
            ).where(
                or_(*chunk)
            ).where(
                models.BadReplicas.state == BadFilesStatus.BAD
            ).values(
                state=BadFilesStatus.DELETED,
                updated_at=datetime.utcnow(),
            )
        session.execute(stmt)
    if dataset_clause:
        for dataset in dataset_clause:
            sub_query = select(
                [1]
            ).where(
                models.BadReplicas.scope == models.DataIdentifierAssociation.child_scope,
                models.BadReplicas.name == models.DataIdentifierAssociation.child_name
            ).where(
                dataset
            )
            stmt = update(
                models.BadReplicas
            ).where(
                exists(sub_query)
            ).where(
                models.BadReplicas.state == BadFilesStatus.BAD
            ).values(
                state=BadFilesStatus.DELETED,
                updated_at=datetime.utcnow(),
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    # Remove content
    if content_clause:
        with Timer('undertaker.content'):
            stmt = delete(
                models.DataIdentifierAssociation
            ).where(
                or_(*content_clause)
            ).execution_options(
                synchronize_session=False
            )
            rowcount = session.execute(stmt).rowcount
        record_counter(name='undertaker.content.rowcount', delta=rowcount)

    # Remove CollectionReplica
    if collection_replica_clause:
        with Timer('undertaker.dids'):
            stmt = delete(
                models.CollectionReplica
            ).where(
                or_(*collection_replica_clause)
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    # Remove generic did metadata
    if metadata_to_delete:
        stmt = delete(
            models.DidMeta
        ).where(
            or_(*metadata_to_delete)
        ).execution_options(
            synchronize_session=False
        )
        if session.bind.dialect.name == 'oracle':
            oracle_version = int(session.connection().connection.version.split('.')[0])
            if oracle_version >= 12:
                with Timer('undertaker.did_meta'):
                    session.execute(stmt)
        else:
            with Timer('undertaker.did_meta'):
                session.execute(stmt)

    # remove data identifier
    if existing_parent_dids:
        # Exit method early to give Judge time to remove locks (Otherwise, due to foreign keys, did removal does not work
        logger(logging.DEBUG, 'Leaving delete_dids early for Judge-Evaluator checks')
        return

    if did_clause:
        with Timer('undertaker.dids'):
            stmt = delete(
                models.DataIdentifier
            ).where(
                or_(*did_clause)
            ).where(
                or_(models.DataIdentifier.did_type == DIDType.CONTAINER,
                    models.DataIdentifier.did_type == DIDType.DATASET)
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)
            if archive_dids:
                insert_deleted_dids(filter_=or_(*did_clause), session=session)

    if did_followed_clause:
        with Timer('undertaker.dids'):
            stmt = delete(
                models.DidsFollowed
            ).where(
                or_(*did_followed_clause)
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    if file_clause:
        stmt = update(
            models.DataIdentifier
        ).where(
            or_(*file_clause)
        ).where(
            models.DataIdentifier.did_type == DIDType.FILE
        ).execution_options(
            synchronize_session=False
        ).values(
            expired_at=None
        )
        session.execute(stmt)


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
    stmt = select(
        models.DataIdentifier
    ).where(
        models.DataIdentifier.scope == scope,
        models.DataIdentifier.name == name,
    ).where(
        or_(models.DataIdentifier.did_type == DIDType.CONTAINER,
            models.DataIdentifier.did_type == DIDType.DATASET)
    )
    try:
        did = session.execute(stmt).scalar_one()
        # Mark for rule re-evaluation
        models.UpdatedDID(
            scope=scope,
            name=name,
            rule_evaluation_action=DIDReEvaluation.DETACH
        ).save(session=session, flush=False)
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    # TODO: should judge target did's status: open, monotonic, close.
    stmt = select(
        models.DataIdentifierAssociation
    ).filter_by(
        scope=scope,
        name=name,
    ).limit(
        1
    )
    if session.execute(stmt).scalar() is None:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' has no child data identifiers." % locals())
    for source in dids:
        if (scope == source['scope']) and (name == source['name']):
            raise exception.UnsupportedOperation('Self-detach is not valid.')
        child_scope = source['scope']
        child_name = source['name']
        associ_did = session.execute(
            stmt.filter_by(
                child_scope=child_scope,
                child_name=child_name
            ).limit(
                1
            )
        ).scalar()
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

    sub_query = select(
        [1]
    ).prefix_with(
        "/*+ INDEX(RULES RULES_SCOPE_NAME_IDX) */", dialect='oracle'
    ).where(
        models.DataIdentifier.scope == models.ReplicationRule.scope,
        models.DataIdentifier.name == models.ReplicationRule.name,
        models.ReplicationRule.state == RuleState.INJECT
    )

    select_stmt = select(
        models.DataIdentifier
    ).with_hint(
        models.DataIdentifier, "index(dids DIDS_IS_NEW_IDX)", 'oracle'
    ).filter_by(
        is_new=True
    ).where(
        ~exists(sub_query)
    )

    if did_type:
        if isinstance(did_type, str):
            select_stmt = select_stmt.filter_by(did_type=DIDType[did_type])
        elif isinstance(did_type, Enum):
            select_stmt = select_stmt.filter_by(did_type=did_type)

    select_stmt = filter_thread_work(session=session, query=select_stmt, total_threads=total_threads, thread_id=thread, hash_variable='name')

    row_count = 0
    for chunk in session.execute(select_stmt).yield_per(10).scalars():
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
            stmt = update(
                models.DataIdentifier
            ).filter_by(
                scope=did['scope'],
                name=did['name']
            ).values(
                is_new=new_flag
            ).execution_options(
                synchronize_session=False
            )
            rowcount = session.execute(stmt).rowcount
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
        stmt = select(
            models.DataIdentifierAssociation
        ).with_hint(
            models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle'
        ).filter_by(
            scope=scope,
            name=name
        )
        for tmp_did in session.execute(stmt).yield_per(5).scalars():
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
        stmt = select(
            models.DataIdentifierAssociationHistory
        ).filter_by(
            scope=scope,
            name=name
        )
        for tmp_did in session.execute(stmt).yield_per(5).scalars():
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

    stmt = select(
        models.DataIdentifierAssociation.scope,
        models.DataIdentifierAssociation.name,
        models.DataIdentifierAssociation.did_type
    ).filter_by(
        child_scope=scope,
        child_name=name
    )
    for did in session.execute(stmt).yield_per(5):
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

    stmt = select(
        models.DataIdentifierAssociation.scope,
        models.DataIdentifierAssociation.name,
        models.DataIdentifierAssociation.did_type
    ).filter_by(
        child_scope=scope,
        child_name=name
    )
    for did in session.execute(stmt).yield_per(5):
        yield {'scope': did.scope, 'name': did.name, 'type': did.did_type}
        # Note that only Python3 supports recursive yield, that's the reason to do the nested for.
        for pdid in list_all_parent_dids(scope=did.scope, name=did.name, session=session):
            yield {'scope': pdid['scope'], 'name': pdid['name'], 'type': pdid['type']}


def list_child_dids_stmt(
        input_dids_table: "Table",
        did_type: DIDType,
):
    """
    Build and returns a query which recursively lists children dids of type `did_type`
    for the dids given as input in a scope/name (temporary) table.

    did_type defines the desired type of DIDs in the result. If set to DIDType.Dataset,
    will only resolve containers and return datasets. If set to DIDType.File, will
    also resolve the datasets and return files.
    """
    if did_type == DIDType.DATASET:
        dids_to_resolve = [DIDType.CONTAINER]
    else:
        dids_to_resolve = [DIDType.CONTAINER, DIDType.DATASET]

    # Uses a recursive SQL CTE (Common Table Expressions)
    initial_set = select(
        models.DataIdentifierAssociation.child_scope,
        models.DataIdentifierAssociation.child_name,
        models.DataIdentifierAssociation.child_type,
    ).join_from(
        input_dids_table,
        models.DataIdentifierAssociation,
        and_(
            models.DataIdentifierAssociation.scope == input_dids_table.scope,
            models.DataIdentifierAssociation.name == input_dids_table.name,
            models.DataIdentifierAssociation.did_type.in_(dids_to_resolve),
        ),
    ).cte(
        recursive=True,
    )

    # Oracle doesn't support union() in recursive CTEs, so use UNION ALL
    # and a "distinct" filter later
    child_datasets_cte = initial_set.union_all(
        select(
            models.DataIdentifierAssociation.child_scope,
            models.DataIdentifierAssociation.child_name,
            models.DataIdentifierAssociation.child_type,
        ).where(
            models.DataIdentifierAssociation.scope == initial_set.c.child_scope,
            models.DataIdentifierAssociation.name == initial_set.c.child_name,
            models.DataIdentifierAssociation.did_type.in_(dids_to_resolve),
        )
    )

    stmt = select(
        child_datasets_cte.c.child_scope.label('scope'),
        child_datasets_cte.c.child_name.label('name'),
    ).distinct(
    ).where(
        child_datasets_cte.c.child_type == did_type,
    )
    return stmt


def list_one_did_childs_stmt(
        scope: "InternalScope",
        name: str,
        did_type: DIDType,
):
    """
    Returns the sqlalchemy query for recursively fetching the child dids of type
    'did_type' for the input did.

    did_type defines the desired type of DIDs in the result. If set to DIDType.Dataset,
    will only resolve containers and return datasets. If set to DIDType.File, will
    also resolve the datasets and return files.
    """
    if did_type == DIDType.DATASET:
        dids_to_resolve = [DIDType.CONTAINER]
    else:
        dids_to_resolve = [DIDType.CONTAINER, DIDType.DATASET]

    # Uses a recursive SQL CTE (Common Table Expressions)
    initial_set = select(
        models.DataIdentifierAssociation.child_scope,
        models.DataIdentifierAssociation.child_name,
        models.DataIdentifierAssociation.child_type,
    ).where(
        models.DataIdentifierAssociation.scope == scope,
        models.DataIdentifierAssociation.name == name,
        models.DataIdentifierAssociation.did_type.in_(dids_to_resolve),
    ).cte(
        recursive=True,
    )

    # Oracle doesn't support union() in recursive CTEs, so use UNION ALL
    # and a "distinct" filter later
    child_datasets_cte = initial_set.union_all(
        select(
            models.DataIdentifierAssociation.child_scope,
            models.DataIdentifierAssociation.child_name,
            models.DataIdentifierAssociation.child_type,
        ).where(
            models.DataIdentifierAssociation.scope == initial_set.c.child_scope,
            models.DataIdentifierAssociation.name == initial_set.c.child_name,
            models.DataIdentifierAssociation.did_type.in_(dids_to_resolve),
        )
    )

    stmt = select(
        child_datasets_cte.c.child_scope.label('scope'),
        child_datasets_cte.c.child_name.label('name'),
    ).distinct(
    ).where(
        child_datasets_cte.c.child_type == did_type,
    )
    return stmt


@transactional_session
def list_child_datasets(
        scope: "InternalScope",
        name: str,
        session: "Optional[Session]" = None
):
    """
    List all child datasets of a container.

    :param scope:     The scope.
    :param name:      The name.
    :param session:   The database session
    :returns:         List of dids
    :rtype:           Generator
    """
    stmt = list_one_did_childs_stmt(scope, name, did_type=DIDType.DATASET)
    result = []
    for row in session.execute(stmt):
        result.append({'scope': row.scope, 'name': row.name})

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
        stmt = select(
            models.DataIdentifier.scope,
            models.DataIdentifier.name,
            models.DataIdentifier.bytes,
            models.DataIdentifier.adler32,
            models.DataIdentifier.guid,
            models.DataIdentifier.events,
            models.DataIdentifier.lumiblocknr,
            models.DataIdentifier.did_type
        ).filter_by(
            scope=scope,
            name=name
        ).with_hint(
            models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
        )
        did = session.execute(stmt).one()

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
            cnt_query = select(
                models.DataIdentifierAssociation.child_scope,
                models.DataIdentifierAssociation.child_name,
                models.DataIdentifierAssociation.child_type
            ).with_hint(
                models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle'
            )

            if long:
                dst_cnt_query = select(
                    models.DataIdentifierAssociation.child_scope,
                    models.DataIdentifierAssociation.child_name,
                    models.DataIdentifierAssociation.child_type,
                    models.DataIdentifierAssociation.bytes,
                    models.DataIdentifierAssociation.adler32,
                    models.DataIdentifierAssociation.guid,
                    models.DataIdentifierAssociation.events,
                    models.DataIdentifier.lumiblocknr
                ).with_hint(
                    models.DataIdentifierAssociation, "INDEX_RS_ASC(DIDS DIDS_PK) INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", "oracle"
                ).where(
                    models.DataIdentifier.scope == models.DataIdentifierAssociation.child_scope,
                    models.DataIdentifier.name == models.DataIdentifierAssociation.child_name
                )
            else:
                dst_cnt_query = select(
                    models.DataIdentifierAssociation.child_scope,
                    models.DataIdentifierAssociation.child_name,
                    models.DataIdentifierAssociation.child_type,
                    models.DataIdentifierAssociation.bytes,
                    models.DataIdentifierAssociation.adler32,
                    models.DataIdentifierAssociation.guid,
                    models.DataIdentifierAssociation.events,
                    bindparam("lumiblocknr", None)
                ).with_hint(
                    models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle'
                )

            dids = [(scope, name, did[7]), ]
            while dids:
                s, n, t = dids.pop()
                if t == DIDType.DATASET:
                    stmt = dst_cnt_query.where(
                        and_(models.DataIdentifierAssociation.scope == s,
                             models.DataIdentifierAssociation.name == n)
                    )

                    for child_scope, child_name, child_type, bytes_, adler32, guid, events, lumiblocknr in session.execute(stmt).yield_per(500):
                        if long:
                            yield {'scope': child_scope, 'name': child_name,
                                   'bytes': bytes_, 'adler32': adler32,
                                   'guid': guid and guid.upper(),
                                   'events': events,
                                   'lumiblocknr': lumiblocknr}
                        else:
                            yield {'scope': child_scope, 'name': child_name,
                                   'bytes': bytes_, 'adler32': adler32,
                                   'guid': guid and guid.upper(),
                                   'events': events}
                else:
                    stmt = cnt_query.filter_by(scope=s, name=n)
                    for child_scope, child_name, child_type in session.execute(stmt).yield_per(500):
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
        sub_stmt = select(
            models.DataIdentifierAssociation.child_name
        ).filter_by(
            scope=scope,
            child_scope=scope
        )
        stmt = select(
            models.DataIdentifier.name,
            models.DataIdentifier.did_type,
            models.DataIdentifier.bytes
        ).filter_by(
            scope=scope
        ).where(
            not_(models.DataIdentifier.name.in_(sub_stmt))
        ).order_by(
            models.DataIdentifier.name
        )
        for row in session.execute(stmt).yield_per(5):
            if row.did_type == DIDType.FILE:
                yield {'scope': scope, 'name': row.name, 'type': row.did_type, 'parent': None, 'level': 0, 'bytes': row.bytes}
            else:
                yield {'scope': scope, 'name': row.name, 'type': row.did_type, 'parent': None, 'level': 0, 'bytes': None}

    def __diddriller(pdid):
        stmt = select(
            models.DataIdentifierAssociation
        ).filter_by(
            scope=pdid['scope'],
            name=pdid['name']
        ).order_by(
            models.DataIdentifierAssociation.child_name
        )
        for row in session.execute(stmt).yield_per(5).scalars():
            parent = {'scope': pdid['scope'], 'name': pdid['name']}
            cdid = {'scope': row.child_scope, 'name': row.child_name, 'type': row.child_type, 'parent': parent, 'level': pdid['level'] + 1}
            yield cdid
            if cdid['type'] != DIDType.FILE and recursive:
                for did in __diddriller(cdid):
                    yield did

    if name is None:
        topdids = __topdids(scope)
    else:
        stmt = select(
            models.DataIdentifier
        ).filter_by(
            scope=scope,
            name=name
        ).limit(
            1
        )
        topdids = session.execute(stmt).scalar()
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
def __get_did(scope, name, session=None):
    try:
        stmt = select(
            models.DataIdentifier
        ).with_hint(
            models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
        ).where(
            models.DataIdentifier.scope == scope,
            models.DataIdentifier.name == name,
        )
        return session.execute(stmt).scalar_one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@read_session
def get_did(scope: "InternalScope", name: str, dynamic_depth: "Optional[DIDType]" = None, session: "Optional[Session]" = None) -> "Dict[str, Any]":
    """
    Retrieve a single data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dynamic_depth: the DID type to use as source for estimation of this DIDs length/bytes.
    If set to None, or to a value which doesn't make sense (ex: requesting depth = CONTAINER for a did of type DATASET)
    will not compute the size dynamically.
    :param session: The database session in use.
    """
    did = __get_did(scope=scope, name=name, session=session)

    bytes_, length = did.bytes, did.length
    if dynamic_depth:
        bytes_, length, events = __resolve_bytes_length_events_did(did=did, dynamic_depth=dynamic_depth, session=session)

    if did.did_type == DIDType.FILE:
        return {'scope': did.scope, 'name': did.name, 'type': did.did_type,
                'account': did.account, 'bytes': bytes_, 'length': 1,
                'md5': did.md5, 'adler32': did.adler32}
    else:
        return {'scope': did.scope, 'name': did.name, 'type': did.did_type,
                'account': did.account, 'open': did.is_open,
                'monotonic': did.monotonic, 'expired_at': did.expired_at,
                'length': length, 'bytes': bytes_}


@read_session
def get_files(files, session=None):
    """
    Retrieve a list of files.

    :param files: A list of files (dictionaries).
    :param session: The database session in use.
    """
    file_condition = []
    for file in files:
        file_condition.append(and_(models.DataIdentifier.scope == file['scope'], models.DataIdentifier.name == file['name']))

    stmt = select(
        models.DataIdentifier.scope,
        models.DataIdentifier.name,
        models.DataIdentifier.bytes,
        models.DataIdentifier.guid,
        models.DataIdentifier.events,
        models.DataIdentifier.availability,
        models.DataIdentifier.adler32,
        models.DataIdentifier.md5
    ).where(
        models.DataIdentifier.did_type == DIDType.FILE
    ).with_hint(
        models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
    ).where(
        or_(*file_condition)
    )

    rows = []
    for row in session.execute(stmt):
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
def set_metadata(scope, name, key, value, did_type=None, did=None,
                 recursive=False, session=None):
    """
    Add single metadata to a data identifier.

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
    Add metadata to a data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param meta: the key-values.
    :param recursive: Option to propagate the metadata change to content.
    :param session: The database session in use.
    """
    did_meta_plugins.set_metadata_bulk(scope=scope, name=name, meta=meta, recursive=recursive, session=session)


@transactional_session
def set_dids_metadata_bulk(dids, recursive=False, session=None):
    """
    Add metadata to a list of data identifiers.

    :param dids: A list of dids including metadata.
    :param recursive: Option to propagate the metadata change to content.
    :param session: The database session in use.
    """

    for did in dids:
        did_meta_plugins.set_metadata_bulk(scope=did['scope'], name=did['name'], meta=did['meta'], recursive=recursive, session=session)


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
def list_parent_dids_bulk(dids, session=None):
    """
    List parent datasets and containers of a did.

    :param dids:               A list of dids.
    :param session:            The database session in use.
    :returns:                  List of dids.
    :rtype:                    Generator.
    """
    condition = []
    for did in dids:
        condition.append(and_(models.DataIdentifierAssociation.child_scope == did['scope'],
                              models.DataIdentifierAssociation.child_name == did['name']))

    try:
        for chunk in chunks(condition, 50):
            stmt = select(
                models.DataIdentifierAssociation.child_scope,
                models.DataIdentifierAssociation.child_name,
                models.DataIdentifierAssociation.scope,
                models.DataIdentifierAssociation.name,
                models.DataIdentifierAssociation.did_type
            ).where(
                or_(*chunk)
            )
            for did_chunk in session.execute(stmt).yield_per(5):
                yield {'scope': did_chunk.scope, 'name': did_chunk.name, 'child_scope': did_chunk.child_scope, 'child_name': did_chunk.child_name, 'type': did_chunk.did_type}
    except NoResultFound:
        raise exception.DataIdentifierNotFound('No Data Identifiers found')


@stream_session
def get_metadata_bulk(dids, inherit=False, session=None):
    """
    Get metadata for a list of dids
    :param dids:               A list of dids.
    :param inherit:            A boolean. If set to true, the metadata of the parent are concatenated.
    :param session:            The database session in use.
    """
    if inherit:
        parent_list = []
        unique_dids = []
        parents = [1, ]
        depth = 0
        for did in dids:
            unique_dids.append((did['scope'], did['name']))
            parent_list.append([(did['scope'], did['name']), ])

        while parents and depth < 20:
            parents = []
            for did in list_parent_dids_bulk(dids, session=session):
                scope = did['scope']
                name = did['name']
                child_scope = did['child_scope']
                child_name = did['child_name']
                if (scope, name) not in unique_dids:
                    unique_dids.append((scope, name))
                if (scope, name) not in parents:
                    parents.append((scope, name))
                for entry in parent_list:
                    if entry[-1] == (child_scope, child_name):
                        entry.append((scope, name))
            dids = [{'scope': did[0], 'name': did[1]} for did in parents]
            depth += 1
        unique_dids = [{'scope': did[0], 'name': did[1]} for did in unique_dids]
        meta_dict = {}
        for did in unique_dids:
            try:
                meta = get_metadata(did['scope'], did['name'], plugin='JSON', session=session)
            except exception.DataIdentifierNotFound:
                meta = {}
            meta_dict[(did['scope'], did['name'])] = meta
        for dids in parent_list:
            result = {'scope': dids[0][0], 'name': dids[0][1]}
            for did in dids:
                for key in meta_dict[did]:
                    if key not in result:
                        result[key] = meta_dict[did][key]
            yield result
    else:
        condition = []
        for did in dids:
            condition.append(and_(models.DataIdentifier.scope == did['scope'],
                                  models.DataIdentifier.name == did['name']))
        try:
            for chunk in chunks(condition, 50):
                stmt = select(
                    models.DataIdentifier
                ).with_hint(
                    models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle'
                ).where(
                    or_(*chunk)
                )
                for row in session.execute(stmt).scalars():
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
    reevaluate_dids_at_close = config_get_bool('subscriptions', 'reevaluate_dids_at_close', raise_exception=False, default=False, session=session)

    update_stmt = update(
        models.DataIdentifier
    ).filter_by(
        scope=scope,
        name=name
    ).prefix_with(
        "/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle'
    ).where(
        or_(models.DataIdentifier.did_type == DIDType.CONTAINER,
            models.DataIdentifier.did_type == DIDType.DATASET)
    ).execution_options(
        synchronize_session=False
    )
    values = {}
    for k in kwargs:
        if k not in statuses:
            raise exception.UnsupportedStatus("The status %(k)s is not a valid data identifier status." % locals())
        if k == 'open':
            if not kwargs[k]:
                update_stmt = update_stmt.filter_by(
                    is_open=True
                ).where(
                    models.DataIdentifier.did_type != DIDType.FILE
                )
                values['is_open'], values['closed_at'] = False, datetime.utcnow()
                values['bytes'], values['length'], values['events'] = __resolve_bytes_length_events_did(did=__get_did(scope=scope, name=name, session=session),
                                                                                                        session=session)
                # Update datasetlocks as well
                stmt = update(
                    models.DatasetLock
                ).filter_by(
                    scope=scope,
                    name=name
                ).values(
                    length=values['length'],
                    bytes=values['bytes']
                )
                session.execute(stmt)

                # Generate a message
                message = {'scope': scope.external,
                           'name': name,
                           'bytes': values['bytes'],
                           'length': values['length'],
                           'events': values['events']}
                if scope.vo != 'def':
                    message['vo'] = scope.vo

                add_message('CLOSE', message, session=session)
                if reevaluate_dids_at_close:
                    set_new_dids(dids=[{'scope': scope, 'name': name}],
                                 new_flag=True,
                                 session=session)

            else:
                # Set status to open only for privileged accounts
                update_stmt = update_stmt.filter_by(
                    is_open=False
                ).where(
                    models.DataIdentifier.did_type != DIDType.FILE
                )
                values['is_open'] = True

                message = {'scope': scope.external, 'name': name}
                if scope.vo != 'def':
                    message['vo'] = scope.vo
                add_message('OPEN', message, session=session)

    update_stmt = update_stmt.values(values)
    rowcount = session.execute(update_stmt).rowcount

    if not rowcount:
        stmt = select(
            models.DataIdentifier
        ).filter_by(
            scope=scope,
            name=name
        )
        try:
            session.execute(stmt).scalar_one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        raise exception.UnsupportedOperation("The status of the data identifier '%(scope)s:%(name)s' cannot be changed" % locals())
    else:
        # Generate callbacks
        if not values['is_open']:
            stmt = select(
                models.ReplicationRule
            ).filter_by(
                scope=scope,
                name=name
            )
            for rule in session.execute(stmt).scalars():
                rucio.core.rule.generate_rule_notifications(rule=rule, session=session)


@stream_session
def list_dids(scope, filters, did_type='collection', ignore_case=False, limit=None,
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
    :param recursive: Recursively list DIDs content.
    :param ignore_dids: List of DIDs to refrain from yielding.
    :param session: The database session in use.
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
            (models.DataIdentifier.suppressed, operator.ne, true()),
        ],
        session=session
    )
    query.with_hint(models.DataIdentifier, 'NO_EXPAND', 'oracle')

    if limit:
        query = query.limit(limit)
    if recursive:
        # Get attached DIDs and save in list because query has to be finished before starting a new one in the recursion
        collections_content = []
        for did in query.yield_per(100):
            if (did.did_type == DIDType.CONTAINER or did.did_type == DIDType.DATASET):
                collections_content += [d for d in list_content(scope=did.scope, name=did.name)]

        # Replace any name filtering with recursed DID names.
        for did in collections_content:
            for or_group in filters:
                or_group['name'] = did['name']
            for result in list_dids(scope=did['scope'], filters=filters, recursive=True, did_type=did_type, limit=limit, offset=offset, long=long, ignore_dids=ignore_dids,
                                    session=session):
                yield result

    if long:
        for did in query.yield_per(5):              # don't unpack this as it makes it dependent on query return order!
            did_full = "{}:{}".format(did.scope, did.name)
            if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                ignore_dids.add(did_full)
                yield {'scope': did.scope, 'name': did.name, 'did_type': str(did.did_type), 'bytes': did.bytes, 'length': did.length}
    else:
        for did in query.yield_per(5):              # don't unpack this as it makes it dependent on query return order!
            did_full = "{}:{}".format(did.scope, did.name)
            if did_full not in ignore_dids:         # concatenating results of OR clauses may contain duplicate DIDs if query result sets not mutually exclusive.
                ignore_dids.add(did_full)
                yield did.name


@read_session
def list_dids_extended(scope, filters, did_type='collection', ignore_case=False, limit=None,
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
    :param recursive: Recursively list DIDs content.
    :param ignore_dids: List of DIDs to refrain from yielding.
    :param session: The database session in use.
    """
    return did_meta_plugins.list_dids(scope, filters, did_type, ignore_case, limit, offset, long, recursive, ignore_dids, session=session)


@read_session
def get_did_atime(scope, name, session=None):
    """
    Get the accessed_at timestamp for a did. Just for testing.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    stmt = select(
        models.DataIdentifier.accessed_at
    ).filter_by(
        scope=scope,
        name=name
    )
    return session.execute(stmt).one()[0]


@read_session
def get_did_access_cnt(scope, name, session=None):
    """
    Get the access_cnt for a did. Just for testing.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    stmt = select(
        models.DataIdentifier.access_cnt
    ).filter_by(
        scope=scope,
        name=name
    )
    return session.execute(stmt).one()[0]


@stream_session
def get_dataset_by_guid(guid, session=None):
    """
    Get the parent datasets for a given GUID.
    :param guid: The GUID.
    :param session: Database session to use.

    :returns: A did.
    """
    stmt = select(
        models.DataIdentifier
    ).filter_by(
        guid=guid,
        did_type=DIDType.FILE
    ).with_hint(
        models.ReplicaLock, "INDEX(DIDS_GUIDS_IDX)", 'oracle'
    )
    try:
        r = session.execute(stmt).scalar_one()
        datasets_stmt = select(
            models.DataIdentifierAssociation.scope,
            models.DataIdentifierAssociation.name
        ).filter_by(
            child_scope=r.scope,
            child_name=r.name
        ).with_hint(
            models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_CHILD_SCOPE_NAME_IDX)", 'oracle'
        )

    except NoResultFound:
        raise exception.DataIdentifierNotFound("No file associated to GUID : %s" % guid)
    for tmp_did in session.execute(datasets_stmt).yield_per(5):
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
            stmt = update(
                models.DataIdentifier
            ).filter_by(
                scope=did['scope'],
                name=did['name'],
                did_type=did['type']
            ).values(
                accessed_at=did.get('accessed_at') or now,
                access_cnt=case([(models.DataIdentifier.access_cnt == none_value, 1)],
                                else_=(models.DataIdentifier.access_cnt + 1))
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)
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
    add_did(scope=output_scope, name=output_name, did_type=DIDType.DATASET, account=account, statuses={}, meta=[], rules=[], lifetime=None, dids=output_files, rse_id=None, session=session)


@transactional_session
def __resolve_bytes_length_events_did(
        did: models.DataIdentifier,
        dynamic_depth: "DIDType" = DIDType.FILE,
        session: "Optional[Session]" = None,
) -> "Tuple[int, int, int]":
    """
    Resolve bytes, length and events of a did

    :did: the DID ORM object for which we perform the resolution
    :param dynamic_depth: the DID type to use as source for estimation of this DIDs length/bytes.
    If set to None, or to a value which doesn't make sense (ex: requesting depth = DATASET for a did of type FILE)
    will not compute the size dynamically.
    :param session: The database session in use.
    """

    if did.did_type == DIDType.DATASET and dynamic_depth == DIDType.FILE or \
            did.did_type == DIDType.CONTAINER and dynamic_depth in (DIDType.FILE, DIDType.DATASET):

        if did.did_type == DIDType.DATASET and dynamic_depth == DIDType.FILE:
            stmt = select(
                func.count(),
                func.sum(models.DataIdentifierAssociation.bytes),
                func.sum(models.DataIdentifierAssociation.events),
            ).where(
                models.DataIdentifierAssociation.scope == did.scope,
                models.DataIdentifierAssociation.name == did.name
            )
        elif did.did_type == DIDType.CONTAINER and dynamic_depth == DIDType.DATASET:
            child_did_stmt = list_one_did_childs_stmt(did.scope, did.name, did_type=DIDType.DATASET).subquery()
            stmt = select(
                func.sum(models.DataIdentifier.length),
                func.sum(models.DataIdentifier.bytes),
                func.sum(models.DataIdentifier.events),
            ).join_from(
                child_did_stmt,
                models.DataIdentifier,
                and_(models.DataIdentifier.scope == child_did_stmt.c.scope,
                     models.DataIdentifier.name == child_did_stmt.c.name),
            )
        else:  # did.did_type == DIDType.CONTAINER and dynamic_depth == DIDType.FILE:
            child_did_stmt = list_one_did_childs_stmt(did.scope, did.name, did_type=DIDType.DATASET).subquery()
            stmt = select(
                func.count(),
                func.sum(models.DataIdentifierAssociation.bytes),
                func.sum(models.DataIdentifierAssociation.events),
            ).join_from(
                child_did_stmt,
                models.DataIdentifierAssociation,
                and_(models.DataIdentifierAssociation.scope == child_did_stmt.c.scope,
                     models.DataIdentifierAssociation.name == child_did_stmt.c.name)
            )

        try:
            length, bytes_, events = session.execute(stmt).one()
            length = length or 0
            bytes_ = bytes_ or 0
            events = events or 0
        except NoResultFound:
            bytes_, length, events = 0, 0, 0
    elif did.did_type == DIDType.FILE:
        bytes_, length, events = did.bytes, 1, did.events
    else:
        bytes_, length, events = did.bytes, did.length, did.events
    return bytes_, length, events


@transactional_session
def resurrect(dids, session=None):
    """
    Resurrect data identifiers.

    :param dids: The list of dids to resurrect.
    :param session: The database session in use.
    """
    for did in dids:
        try:
            stmt = select(
                models.DeletedDataIdentifier
            ).with_hint(
                models.DeletedDataIdentifier, "INDEX(DELETED_DIDS DELETED_DIDS_PK)", 'oracle'
            ).filter_by(
                scope=did['scope'],
                name=did['name']
            )
            del_did = session.execute(stmt).scalar_one()
        except NoResultFound:
            # Dataset might still exist, but could have an expiration date, if it has, remove it
            stmt = update(
                models.DataIdentifier
            ).where(
                models.DataIdentifier.scope == did['scope'],
                models.DataIdentifier.name == did['name'],
                models.DataIdentifier.expired_at < datetime.utcnow()
            ).execution_options(
                synchronize_session=False
            ).values(
                expired_at=None
            )
            rowcount = session.execute(stmt).rowcount
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

        stmt = delete(
            models.DeletedDataIdentifier
        ).prefix_with(
            "/*+ INDEX(DELETED_DIDS DELETED_DIDS_PK) */", dialect='oracle'
        ).filter_by(
            scope=did['scope'],
            name=did['name']
        )
        session.execute(stmt)

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
        stmt = select(
            models.ConstituentAssociation
        ).with_hint(
            models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle'
        ).filter_by(
            scope=scope,
            name=name
        )

        for tmp_did in session.execute(stmt).yield_per(5).scalars():
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
            stmt = select(
                models.DataIdentifier
            ).filter_by(
                scope=did['scope'],
                name=did['name']
            )
            did = session.execute(stmt).scalar_one()
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
        stmt = select(
            models.DidsFollowed
        ).filter_by(
            scope=scope,
            name=name
        )
        for user in session.execute(stmt).scalars().all():
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
            stmt = delete(
                models.DidsFollowed
            ).filter_by(
                scope=did['scope'],
                name=did['name'],
                account=account
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)
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
        stmt = select(
            models.DidsFollowed
        ).filter_by(
            scope=scope,
            name=name
        )
        for did in session.execute(stmt).scalars().all():
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
    stmt = select(
        models.FollowEvents
    ).order_by(
        models.FollowEvents.created_at
    )

    # Use hearbeat mechanism to select a chunck of events based on the hashed account
    stmt = filter_thread_work(session=session, query=stmt, total_threads=total_workers, thread_id=worker_number, hash_variable='account')

    try:
        events = session.execute(stmt).scalars().all()
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
                stmt = delete(
                    models.FollowEvents
                ).filter_by(
                    scope=event.scope,
                    name=event.name,
                    account=event.account
                ).execution_options(
                    synchronize_session=False
                )
                session.execute(stmt)

            body += "Thank You."
            # Get the email associated with the account.
            stmt = select(
                models.Account.email
            ).filter_by(
                account=account
            )
            email = session.execute(stmt).scalar()
            add_message('email', {'to': email,
                                  'subject': 'Report of affected dataset(s)',
                                  'body': body})

    except NoResultFound:
        raise exception.AccountNotFound("No email found for given account.")


@transactional_session
def insert_content_history(filter_, did_created_at, session=None):
    """
    Insert into content history a list of did

    :param filter_: Content clause of the files to archive
    :param did_created_at: Creation date of the did
    :param session: The database session in use.
    """
    new_did_created_at = did_created_at
    stmt = select(
        models.DataIdentifierAssociation.scope,
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
        models.DataIdentifierAssociation.updated_at
    ).where(
        filter_
    )
    for cont in session.execute(stmt).all():
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
def insert_deleted_dids(filter_, session=None):
    """
    Insert into deleted_dids a list of did

    :param filter_: The database filter to retrieve dids for archival
    :param session: The database session in use.
    """
    stmt = select(
        models.DataIdentifier.scope,
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
        models.DataIdentifier.access_cnt
    ).where(
        filter_
    )

    for did in session.execute(stmt).all():
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
