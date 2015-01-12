# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2014
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2014
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2014

import logging
import sys

from datetime import datetime, timedelta
from hashlib import md5
from re import match

from sqlalchemy import and_, or_
from sqlalchemy.exc import DatabaseError, IntegrityError, CompileError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import not_, func
from sqlalchemy.sql.expression import bindparam, text

import rucio.core.rule
import rucio.core.replica  # import add_replicas

from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.constants import reserved_keys
from rucio.core.message import add_message
from rucio.core.monitor import record_timer_block, record_counter
from rucio.db import models
from rucio.db.constants import DIDType, DIDReEvaluation
from rucio.db.enum import EnumSymbol
from rucio.db.session import read_session, transactional_session, stream_session


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


@read_session
def list_expired_dids(worker_number=None, total_workers=None, limit=None, session=None):
    """
    List expired data identifiers.

    :param limit: limit number.
    :param session: The database session in use.
    """
    query = session.query(models.DataIdentifier.scope, models.DataIdentifier.name, models.DataIdentifier.did_type).\
        filter(models.DataIdentifier.expired_at < datetime.utcnow()).\
        order_by(models.DataIdentifier.expired_at).\
        with_hint(models.DataIdentifier, "index(DIDS DIDS_EXPIRED_AT_IDX)", 'oracle')

    if worker_number and total_workers and total_workers - 1 > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number-1), bindparam('total_workers', total_workers-1)]
            query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_workers - 1, worker_number - 1))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers-1, worker_number-1))
        elif session.bind.dialect.name == 'sqlite':
            row_count = 0
            dids = list()
            for scope, name, did_type in query.yield_per(10):
                if int(md5(name).hexdigest(), 16) % total_workers == worker_number-1:
                    dids.append({'scope': scope, 'name': name, 'did_type': did_type})
                    row_count += 1
                if limit and row_count >= limit:
                    return dids
            return dids

    if limit:
        query = query.limit(limit)

    return [{'scope': scope, 'name': name, 'did_type': did_type} for scope, name, did_type in query]


@transactional_session
def add_did(scope, name, type, account, statuses={}, meta=[], rules=[], lifetime=None, session=None):
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
    :param session: The database session in use.
    """
    return add_dids(dids=[{'scope': scope, 'name': name, 'type': type, 'statuses': statuses, 'meta': meta, 'rules': rules, 'lifetime': lifetime}], account=account, session=session)


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

                if isinstance(did['type'], str) or isinstance(did['type'], unicode):
                    did['type'] = DIDType.from_sym(did['type'])

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
                # Add metadata
                # ToDo: metadata validation
                # validate_meta(did.get('meta', {}))
                for key in did.get('meta', {}):
                    new_did.update({key: did['meta'][key]})

                new_did.save(session=session, flush=False)

                if did.get('rules', None):
                    rucio.core.rule.add_rules(dids=[did, ], rules=did['rules'], session=session)

                event_type = None
                if did['type'] == DIDType.CONTAINER:
                    event_type = 'REGISTER_CNT'
                if did['type'] == DIDType.DATASET:
                    event_type = 'REGISTER_DTS'
                if event_type:
                    add_message(event_type, {'account': account,
                                             'scope': did['scope'],
                                             'name': did['name'],
                                             'expires': expired_at},
                                session=session)

            except KeyError, e:
                # ToDo
                raise

        session.flush()

    except IntegrityError, e:
        if e.args[0] == "(IntegrityError) columns scope, name are not unique" \
                or match('.*IntegrityError.*ORA-00001: unique constraint.*DIDS_PK.*violated.*', e.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', e.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', e.args[0]):
            raise exception.DataIdentifierAlreadyExists('Data Identifier already exists!')

        if e.args[0] == "(IntegrityError) foreign key constraint failed" \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', e.args[0]) \
                or match('.*IntegrityError.*02291.*integrity constraint.*DIDS_SCOPE_FK.*violated - parent key not found.*', e.args[0]) \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint.*', e.args[0]):
            raise exception.ScopeNotFound('Scope not found!')
        raise exception.RucioException(e.args)
    except DatabaseError, e:
        if match('.*(DatabaseError).*ORA-14400.*inserted partition key does not map to any partition.*', e.args[0]):
            raise exception.ScopeNotFound('Scope not found!')
        raise exception.RucioException(e.args)


@transactional_session
def __add_files_to_dataset(scope, name, files, account, rse, session):
    """
    Add files to dataset.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param files: .
    :param account: The account owner.
    :param rse: The RSE name for the replicas.
    :param session: The database session in use.
    """
    if rse:
        rucio.core.replica.add_replicas(rse=rse, files=files, account=account, session=session)

    files = get_files(files=files, session=session)
    for file in files:
        did_asso = models.DataIdentifierAssociation(scope=scope, name=name, child_scope=file['scope'], child_name=file['name'],
                                                    bytes=file['bytes'], adler32=file.get('adler32'),
                                                    guid=file['guid'], events=file['events'],
                                                    md5=file.get('md5'), did_type=DIDType.DATASET, child_type=DIDType.FILE, rule_evaluation=True)
        did_asso.save(session=session, flush=False)
    try:
        session.flush()
    except IntegrityError, e:
        if match('.*IntegrityError.*ORA-02291: integrity constraint .*CONTENTS_CHILD_ID_FK.*violated - parent key not found.*', e.args[0]) \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', e.args[0]) \
                or e.args[0] == "(IntegrityError) foreign key constraint failed" \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint.*', e.args[0]):
            raise exception.DataIdentifierNotFound("Data identifier not found")
        elif match('.*IntegrityError.*ORA-00001: unique constraint .*CONTENTS_PK.*violated.*', e.args[0]) \
                or match('.*columns scope, name, child_scope, child_name are not unique.*', e.args[0]):
            raise exception.FileAlreadyExists(e.args)
        else:
            raise exception.RucioException(e.args)


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

    condition = or_()
    for c in collections:

        if (scope == c['scope']) and (name == c['name']):
            raise exception.UnsupportedOperation('Self-append is not valid!')

        condition.append(and_(models.DataIdentifier.scope == c['scope'],
                              models.DataIdentifier.name == c['name']))

    available_dids = {}
    child_type = None
    for row in session.query(models.DataIdentifier.scope, models.DataIdentifier.name, models.DataIdentifier.did_type).filter(condition):

        if row.did_type == DIDType.FILE:
            raise exception.UnsupportedOperation("Adding a file (%s:%s) to a container (%s:%s) is forbidden" % (row.scope, row.name, scope, name))

        if not child_type:
            child_type = row.did_type

        available_dids[row.scope + row.name] = row.did_type

        if child_type != row.did_type:
            raise exception.UnsupportedOperation("Mixed collection is not allowed: '%s:%s' is a %s(expected type: %s)" % (row.scope, row.name, row.did_type, child_type))

    for c in collections:
        did_asso = models.DataIdentifierAssociation(scope=scope, name=name, child_scope=c['scope'], child_name=c['name'],
                                                    did_type=DIDType.CONTAINER, child_type=available_dids.get(c['scope'] + c['name']), rule_evaluation=True)
        did_asso.save(session=session, flush=False)
    try:
        session.flush()
    except IntegrityError, e:
        raise exception.RucioException(e.args)


@transactional_session
def attach_dids(scope, name, dids, account, rse=None, session=None):
    """
    Append data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param account: The account owner.
    :param rse: The RSE name for the replicas.
    :param session: The database session in use.
    """
    return attach_dids_to_dids(attachments=[{'scope': scope, 'name': name, 'dids': dids, 'rse': rse}], account=account, session=session)


@transactional_session
def attach_dids_to_dids(attachments, account, session=None):
    """
    Append content to dids.

    :param attachments: The contents.
    :param account: The account.
    :param session: The database session in use.
    """
    parent_did_condition = list()
    parent_dids = list()
    for attachment in attachments:
        try:
            parent_did = session.query(models.DataIdentifier).filter_by(scope=attachment['scope'], name=attachment['name']).\
                filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET)).\
                one()

            if not parent_did.is_open:
                raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is closed" % attachment)

            if parent_did.did_type == DIDType.FILE:
                raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is a file" % attachment)
            elif parent_did.did_type == DIDType.DATASET:
                __add_files_to_dataset(scope=attachment['scope'], name=attachment['name'], files=attachment['dids'], account=account, rse=attachment['rse'], session=session)
            elif parent_did.did_type == DIDType.CONTAINER:
                __add_collections_to_container(scope=attachment['scope'], name=attachment['name'], collections=attachment['dids'], account=account, session=session)

            parent_did_condition.append(and_(models.DataIdentifier.scope == parent_did.scope,
                                             models.DataIdentifier.name == parent_did.name))
            parent_dids.append((parent_did.scope, parent_did.name))
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (attachment['scope'], attachment['name']))

    for scope, name in parent_dids:
        models.UpdatedDID(scope=scope, name=name, rule_evaluation_action=DIDReEvaluation.ATTACH).save(session=session, flush=False)

    # is_none = None
    # rowcount = session.query(models.DataIdentifier).filter(or_(*parent_did_condition)).\
    #    update({'rule_evaluation_required': datetime.utcnow(),
    #            'rule_evaluation_action': case([(models.DataIdentifier.rule_evaluation_action == DIDReEvaluation.DETACH, DIDReEvaluation.BOTH.value),
    #                                            (models.DataIdentifier.rule_evaluation_action == is_none, DIDReEvaluation.ATTACH.value),
    #                                            ], else_=models.DataIdentifier.rule_evaluation_action)},
    #           synchronize_session=False)    # increase(rse_id=replica_rse.id, delta=nbfiles, bytes=bytes, session=session)


@transactional_session
def delete_dids(dids, account, session=None):
    """
    Delete data identifiers

    :param dids: The list of dids to delete.
    :param account: The account.
    :param session: The database session in use.
    """

    rule_id_clause = []
    content_clause = []
    parent_content_clause = []
    did_clause = []
    for did in dids:
        logging.info('Removing did %s:%s' % (did['scope'], did['name']))
        did_clause.append(and_(models.DataIdentifier.scope == did['scope'], models.DataIdentifier.name == did['name']))
        parent_content_clause.append(and_(models.DataIdentifierAssociation.child_scope == did['scope'], models.DataIdentifierAssociation.child_name == did['name']))
        rule_id_clause.append(and_(models.ReplicationRule.scope == did['scope'], models.ReplicationRule.name == did['name']))
        content_clause.append(and_(models.DataIdentifierAssociation.scope == did['scope'], models.DataIdentifierAssociation.name == did['name']))

        # Send message for AMI
        add_message('ERASE', {'account': account,
                              'scope': did['scope'],
                              'name': did['name']},
                    session=session)

    # Delete rules on did
    if rule_id_clause:
        with record_timer_block('undertaker.rules'):
            for (rule_id, scope, name, rse_expression, ) in session.query(models.ReplicationRule.id,
                                                                          models.ReplicationRule.scope,
                                                                          models.ReplicationRule.name,
                                                                          models.ReplicationRule.rse_expression).filter(or_(*rule_id_clause)):
                logging.debug('Removing rule %s for did %s:%s on RSE-Expression %s' % (str(rule_id), scope, name, rse_expression))
                rucio.core.rule.delete_rule(rule_id=rule_id, nowait=True, session=session)

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
        record_counter(counters='undertaker.content.rowcount',  delta=rowcount)

    # remove data identifier
    if existing_parent_dids:
        # Exit method early to give Judge time to remove locks (Otherwise, due to foreign keys, did removal does not work
        logging.debug('Leaving delete_dids early for Judge-Evaluator checks')
        return
    with record_timer_block('undertaker.dids'):
        rowcount = session.query(models.DataIdentifier).filter(or_(*did_clause)).\
            filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET)).\
            delete(synchronize_session=False)


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
        associ_did.delete(session=session)


@stream_session
def list_new_dids(did_type, worker_number=None, total_workers=None, chunk_size=1000, session=None):
    """
    List recent identifiers.

    :param did_type : The DID type.
    :param session: The database session in use.
    """
    query = session.query(models.DataIdentifier).filter_by(is_new=True).with_hint(models.DataIdentifier, "index(dids DIDS_IS_NEW_IDX)", 'oracle')
    if did_type:
        if (isinstance(did_type, str) or isinstance(did_type, unicode)):
            query = query.filter_by(did_type=DIDType.from_sym(did_type))
        elif isinstance(did_type, EnumSymbol):
            query = query.filter_by(did_type=did_type)
    if worker_number and total_workers and total_workers - 1 > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number-1), bindparam('total_workers', total_workers-1)]
            query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_workers - 1, worker_number - 1))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers-1, worker_number-1))
        elif session.bind.dialect.name == 'sqlite':
            row_count = 0
            for chunk in query.yield_per(10):
                if int(md5(chunk.name).hexdigest(), 16) % total_workers == worker_number-1:
                    # dids.append({'scope': scope, 'name': name, 'did_type': did_type})
                    row_count += 1
                    if row_count <= chunk_size:
                        yield {'scope': chunk.scope, 'name': chunk.name, 'did_type': chunk.did_type}
                    else:
                        break
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
    for did in dids:
        try:
            # session.query(models.DataIdentifier).filter_by(scope=did['scope'], name=did['name']).with_for_update(nowait=True).first()
            # session.query(models.DataIdentifier).filter_by(scope=did['scope'], name=did['name']).first()
            rowcount = session.query(models.DataIdentifier).filter_by(scope=did['scope'], name=did['name']).update({'is_new': new_flag}, synchronize_session=False)
            if not rowcount:
                raise exception.DataIdentifierNotFound("Data identifier '%s:%s' not found" % (did['scope'], did['name']))
        except DatabaseError, e:
            raise exception.DatabaseException('%s : Cannot update %s:%s' % (e.args[0], did['scope'], did['name']))
    try:
        session.flush()
    except IntegrityError, e:
        raise exception.RucioException(e.args[0])
    except DatabaseError, e:
        raise exception.RucioException(e.args[0])
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
    List all parent datasets and containers of a did, no matter on what level

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
        list_all_parent_dids(scope=did.scope, name=did.name, session=session)


@stream_session
def list_child_datasets(scope, name, session=None):
    """
    List all child datasets of a container.

    :param scope:     The scope.
    :param name:      The name.
    :param session:   The database session
    :returns:         List of dids
    :rtype:           Generator
    """

    query = session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.child_type).filter(models.DataIdentifierAssociation.scope == scope,
                                                                              models.DataIdentifierAssociation.name == name,
                                                                              models.DataIdentifierAssociation.child_type != DIDType.FILE)
    query = query.with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
    for child_scope, child_name, child_type in query.yield_per(5):
        if child_type == DIDType.CONTAINER:
            list_child_datasets(scope=child_scope, name=child_name, session=session)
        else:
            yield {'scope': child_scope, 'name': child_name, 'type': child_type}


@stream_session
def list_files(scope, name, long=False, session=None):
    """
    List data identifier file contents.

    :param scope:      The scope name.
    :param name:       The data identifier name.
    :param long:       A boolean to choose if GUID is returned or not.
    :param session:    The database session in use.
    """
    try:
        did = session.query(models.DataIdentifier.scope, models.DataIdentifier.name, models.DataIdentifier.bytes, models.DataIdentifier.adler32, models.DataIdentifier.guid,
                            models.DataIdentifier.events, models.DataIdentifier.lumiblocknr, models.DataIdentifier.did_type).filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').one()
        if did[7] == DIDType.FILE:
            if long:
                yield {'scope': did[0], 'name': did[1], 'bytes': did[2], 'adler32': did[3], 'guid': did[4] and did[4].upper(), 'events': did[5], 'lumiblocknr': did[6]}
            else:
                yield {'scope': did[0], 'name': did[1], 'bytes': did[2], 'adler32': did[3], 'guid': did[4] and did[4].upper(), 'events': did[5]}
        else:
            query = session.query(models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.child_name, models.DataIdentifierAssociation.child_type, models.DataIdentifierAssociation.bytes,
                                  models.DataIdentifierAssociation.adler32, models.DataIdentifierAssociation.guid, models.DataIdentifierAssociation.events).\
                with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
            dids = [(scope, name), ]
            while dids:
                s, n = dids.pop()
                for child_scope, child_name, child_type, bytes, adler32, guid, events in query.filter_by(scope=s, name=n).yield_per(5):
                    if child_type == DIDType.FILE:
                        if long:
                            child_did_query = session.query(models.DataIdentifier).filter_by(scope=child_scope, name=child_name).one()
                            yield {'scope': child_scope, 'name': child_name,
                                   'bytes': bytes, 'adler32': adler32, 'guid': guid and guid.upper(), 'events': events, 'lumiblocknr': child_did_query.lumiblocknr}
                        else:
                            yield {'scope': child_scope, 'name': child_name,
                                   'bytes': bytes, 'adler32': adler32, 'guid': guid and guid.upper(), 'events': events}
                    else:
                        dids.append((child_scope, child_name))
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
        q = session.query(models.DataIdentifier.name, models.DataIdentifier.did_type).filter_by(scope=scope)  # add type
        s = q.filter(not_(models.DataIdentifier.name.in_(c))).order_by(models.DataIdentifier.name)
        for row in s.yield_per(5):
            yield {'scope': scope, 'name': row.name, 'type': row.did_type, 'parent': None, 'level': 0}

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
def get_did(scope, name, session=None):
    """
    Retrieve a single data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        r = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').one()
        if r.did_type == DIDType.FILE:
            did_r = {'scope': r.scope, 'name': r.name, 'type': r.did_type, 'account': r.account}
        else:
            did_r = {'scope': r.scope, 'name': r.name, 'type': r.did_type,
                     'account': r.account, 'open': r.is_open, 'monotonic': r.monotonic, 'expired_at': r.expired_at,
                     'length': r.length, 'bytes': r.bytes}
        return did_r
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
                                models.DataIdentifier.events,
                                models.DataIdentifier.adler32, models.DataIdentifier.md5).\
        filter(models.DataIdentifier.did_type == DIDType.FILE).\
        with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
    file_condition = []
    for file in files:
        file_condition.append(and_(models.DataIdentifier.scope == file['scope'], models.DataIdentifier.name == file['name']))

    rows = [row._asdict() for row in files_query.filter(or_(*file_condition))]

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
def set_metadata(scope, name, key, value, type=None, did=None, session=None):
    """
    Add metadata to data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param key: the key.
    :param value: the value.
    :paran did: The data identifier info.
    :param session: The database session in use.
    """

    if key in reserved_keys:
        raise exception.InvalidValueForKey("%s is a reserved key and cannot be used." % key)

    if key == 'lifetime':
        try:
            expired_at = datetime.utcnow() + timedelta(seconds=value)
            session.query(models.DataIdentifier).filter_by(scope=scope, name=name).update({'expired_at': expired_at}, synchronize_session='fetch')
        except TypeError, e:
            raise exception.InvalidValueForKey(e)
    else:
        try:
            session.query(models.DataIdentifier).filter_by(scope=scope, name=name).update({key: value}, synchronize_session='fetch')  # add DIDtype
        except CompileError, e:
            raise exception.InvalidMetadata(e)


@read_session
def get_metadata(scope, name, session=None):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        row = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').one()
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        return d
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
#    try:
#        r = session.query(models.DataIdentifier.__table__).filter_by(scope=scope, name=name).one()   # remove deleted data
#    except NoResultFound:
#        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
#    for key in session.query(models.DIDKey):
#        models.DataIdentifier.__table__.append_column(Column(key.key, models.String(50)))
#    meta = {}
#    for column in r._fields:
#        meta[column] = getattr(r, column)

    # if r.did_type == DIDType.FILE and r.guid:
    #    meta['guid'] = r.guid


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
        with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').\
        filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET))
    values = {}
    for k in kwargs:
        if k not in statuses:
            raise exception.UnsupportedStatus("The status %(k)s is not a valid data identifier status." % locals())
        if k == 'open':
            if not kwargs[k]:
                query = query.filter_by(is_open=True).filter(models.DataIdentifier.did_type != DIDType.FILE)
                values['is_open'] = False
                values['length'], values['bytes'], values['events'] = session.query(func.count(models.DataIdentifierAssociation.scope),
                                                                                    func.sum(models.DataIdentifierAssociation.bytes),
                                                                                    func.sum(models.DataIdentifierAssociation.events)).filter_by(scope=scope, name=name).one()
                # Update datasetlocks as well
                session.query(models.DatasetLock).filter_by(scope=scope, name=name).update({'length': values['length'], 'bytes': values['bytes']})
            else:
                # Set status to open only for privileged accounts
                query = query.filter_by(is_open=False).filter(models.DataIdentifier.did_type != DIDType.FILE)
                values['is_open'] = True

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
                rucio.core.rule.generate_message_for_dataset_ok_callback(rule=rule, session=session)


@stream_session
def list_dids(scope, filters, type='collection', ignore_case=False, limit=None, offset=None, session=None):
    """
    Search data identifiers

    :param scope: the scope name.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param type: the type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
    :param ignore_case: ignore case distinctions.
    :param limit: limit number.
    :param offset: offset number.
    :param session: The database session in use.
    """
    types = ['all', 'collection', 'container', 'dataset', 'file']
    if type not in types:
        raise exception.UnsupportedOperation("Valid type are: %(types)s" % locals())

    query = session.query(models.DataIdentifier.name).filter(models.DataIdentifier.scope == scope)
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

        if not hasattr(models.DataIdentifier, k):
            raise exception.KeyNotFound(k)

        if (isinstance(v, unicode) or isinstance(v, str)) and ('*' in v or '%' in v):
            if session.bind.dialect.name == 'postgresql':  # PostgreSQL escapes automatically
                query = query.filter(getattr(models.DataIdentifier, k).like(v.replace('*', '%')))
            else:
                query = query.filter(getattr(models.DataIdentifier, k).like(v.replace('*', '%'), escape='\\'))
        else:
            query = query.filter(getattr(models.DataIdentifier, k) == v)

    if 'name' in filters and '*' in filters['name']:
        query = query.with_hint(models.DataIdentifier, "NO_INDEX(dids(SCOPE,NAME))", 'oracle')

    if limit:
        query = query.limit(limit)

    for name in query.yield_per(5):
        yield name


@read_session
def get_did_atime(scope, name, session=None):
    """
    Get the accessed_at timestamp for a replica. Just for testing.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    return session.query(models.DataIdentifier.accessed_at).filter_by(scope=scope, name=name).one()[0]


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
            with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS_CHILD_SCOPE_NAME_IDX)", 'oracle')
    except NoResultFound:
        raise exception.DataIdentifierNotFound("No file associated to GUID : %s" % guid)
    for tmp_did in datasets.yield_per(5):
        yield {'scope': tmp_did.scope, 'name': tmp_did.name}


@transactional_session
def touch_dids(dids, session=None):
    """
    Update the accessed_at timestamp of the given dids.

    :param replicas: the list of dids.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """

    now = datetime.utcnow()
    try:
        for did in dids:
            session.query(models.DataIdentifier).filter_by(scope=did['scope'], name=did['name'], did_type=did['type']).\
                update({'accessed_at': did.get('accessed_at') or now}, synchronize_session=False)
    except DatabaseError:
        return False

    return True
