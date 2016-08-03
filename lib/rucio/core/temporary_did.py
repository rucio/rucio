"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
"""

from datetime import datetime

from sqlalchemy import and_, or_
from sqlalchemy.sql.expression import bindparam, case, text

from rucio.core.did import attach_dids
from rucio.core.rse import get_rse, get_rse_id
from rucio.core.replica import add_replica
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session
# from rucio.rse import rsemanager as rsemgr


@transactional_session
def add_temporary_dids(dids, account, session=None):
    """
    Bulk add temporary data identifiers.

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    temporary_dids, rses = [], {}
    for did in dids:

        rse = did['rse']
        if rse not in rses:
            if did.get('rse_id'):
                rses[rse] = {'id': did['rse_id']}
            else:
                replica_rse = get_rse(rse=rse, session=session)
                rses[rse] = {'id': replica_rse.id}

        if did.get('pfn'):
            did['path'] = did['pfn']
            # In waiting to properly extract the path
            # p = rsemgr.create_protocol(rse_settings=rsemgr.get_rse_info(rse, session=session), operation='write', scheme=scheme)
            # if not replica_rse.deterministic:
            #   pfns = p.parse_pfns(pfns=pfns)
            #   tmp = pfns[file['pfn']]
            # file['path'] = ''.join([tmp['path'], tmp['name']])

        temporary_dids.append({'scope': did['scope'],
                               'name': did['name'],
                               'rse_id': rses[rse]['id'],
                               'path': did.get('path'),
                               'bytes': did.get('bytes'),
                               'md5': did.get('md5'),
                               'adler32': did.get('adler32'),
                               'guid': did.get('guid'),
                               'events': did.get('envents'),
                               'parent_scope': did.get('parent_scope'),
                               'parent_name': did.get('parent_name'),
                               'offset': did.get('offset'),
                               'expired_at': datetime.utcnow()})
    try:
        session.bulk_insert_mappings(models.TemporaryDataIdentifier, temporary_dids)
    except:
        raise


@transactional_session
def compose(scope, name, rse, bytes, sources, account,
            md5=None, adler32=None, pfn=None, meta={}, rules=[],
            parent_scope=None, parent_name=None,
            session=None):
    """
    Concatenates a list of existing dids into a new file replica

    :param scope: the scope name.
    :param name: The data identifier name.
    :param rse: the rse name.
    :param bytes: the size of the file.
    :sources sources: The list of temporary DIDs.
    :param account: The account owner.
    :param md5: The md5 checksum.
    :param adler32: The adler32 checksum.
    :param pfn: Physical file name (for nondeterministic rse).
    :param meta: Meta-data associated with the file. Represented as key/value pairs in a dictionary.
    :param rules: Replication rules associated with the file. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param parent_scope: Possible dataset scope.
    :param parent_name: Possibe dataset name.
    :param session: The database session in use.
    """
    # Create the new file did and replica
    add_replica(rse=rse, scope=scope, name=name, bytes=bytes, account=account,
                adler32=adler32, md5=md5, pfn=pfn, meta=meta, rules=rules,
                session=session)

    # Attach the file to a dataset
    if parent_scope and parent_name:
        attach_dids(scope=parent_scope, name=parent_name,
                    dids=[{'scope': scope, 'name': name}], account=account,
                    rse=None, session=session)

    # Mark the merged dids as obsolete
    now, expired_dids = datetime.utcnow(), []
    for source in sources:
        expired_dids.append({'scope': source['scope'],
                             'name': source['name'],
                             'expired_at': now})
    session.bulk_update_mappings(models.TemporaryDataIdentifier, expired_dids)


@read_session
def list_expired_temporary_dids(rse, limit, worker_number=None, total_workers=None,
                                session=None):
    """
    List expired temporary DIDs.

    :param rse: the rse name.
    :param limit: The maximum number of replicas returned.
    :param worker_number:      id of the executing worker.
    :param total_workers:      Number of total workers.
    :param session: The database session in use.

    :returns: a list of dictionary replica.
    """
    rse_id = get_rse_id(rse, session=session)
    is_none = None
    query = session.query(models.TemporaryDataIdentifier.scope,
                          models.TemporaryDataIdentifier.name,
                          models.TemporaryDataIdentifier.path,
                          models.TemporaryDataIdentifier.bytes).\
        with_hint(models.TemporaryDataIdentifier, "INDEX(tmp_dids TMP_DIDS_EXPIRED_AT_IDX)", 'oracle').\
        filter(case([(models.TemporaryDataIdentifier.expired_at != is_none, models.TemporaryDataIdentifier.rse_id), ]) == rse_id)

    if worker_number and total_workers and total_workers - 1 > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number - 1), bindparam('total_workers', total_workers - 1)]
            query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_workers - 1, worker_number - 1))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(path))::bit(32)::int), %s) = %s' % (total_workers - 1, worker_number - 1))

    return [{'path': path,
             'rse': rse,
             'rse_id': rse_id,
             'scope': scope,
             'name': name,
             'bytes': bytes}
            for scope, name, path, bytes in query.limit(limit)]


@transactional_session
def delete_temporary_dids(dids, session=None):
    """
    Delete file replicas.

    :param rse: the rse name.
    :param files: the list of files to delete.
    :param session
    """
    where_clause = []
    for did in dids:
        where_clause.append(and_(models.TemporaryDataIdentifier.scope == did['scope'],
                                 models.TemporaryDataIdentifier.name == did['name']))

    if where_clause:
        return session.query(models.TemporaryDataIdentifier).\
            with_hint(models.TemporaryDataIdentifier, "INDEX(tmp_dids TMP_DIDS_PK)", 'oracle').\
            filter(or_(*where_clause)).delete(synchronize_session=False)
    return
