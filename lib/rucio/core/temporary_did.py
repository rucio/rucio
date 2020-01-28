"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2017
  - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
  - Brandon White <bjwhite@fnal.gov>, 2019-2020

  PY3K COMPATIBLE
"""

from datetime import datetime

from sqlalchemy import and_, or_, func
from sqlalchemy.sql.expression import case

from rucio.core.did import attach_dids
from rucio.core.replica import add_replica
from rucio.db.sqla import models, filter_thread_work
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
    temporary_dids = []
    for did in dids:

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
                               'rse_id': did['rse_id'],
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
def compose(scope, name, rse_id, bytes, sources, account,
            md5=None, adler32=None, pfn=None, meta={}, rules=[],
            parent_scope=None, parent_name=None,
            session=None):
    """
    Concatenates a list of existing dids into a new file replica

    :param scope: the scope name.
    :param name: The data identifier name.
    :param rse_id: the rse id.
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
    add_replica(rse_id=rse_id, scope=scope, name=name, bytes=bytes, account=account,
                adler32=adler32, md5=md5, pfn=pfn, meta=meta, rules=rules,
                session=session)

    # Attach the file to a dataset
    if parent_scope and parent_name:
        attach_dids(scope=parent_scope, name=parent_name,
                    dids=[{'scope': scope, 'name': name}], account=account,
                    rse_id=None, session=session)

    # Mark the merged dids as obsolete
    now, expired_dids = datetime.utcnow(), []
    for source in sources:
        expired_dids.append({'scope': source['scope'],
                             'name': source['name'],
                             'expired_at': now})
    session.bulk_update_mappings(models.TemporaryDataIdentifier, expired_dids)


@read_session
def list_expired_temporary_dids(rse_id, limit, worker_number=None, total_workers=None,
                                session=None):
    """
    List expired temporary DIDs.

    :param rse_id: the rse id.
    :param limit: The maximum number of replicas returned.
    :param worker_number:      id of the executing worker.
    :param total_workers:      Number of total workers.
    :param session: The database session in use.

    :returns: a list of dictionary replica.
    """
    is_none = None
    query = session.query(models.TemporaryDataIdentifier.scope,
                          models.TemporaryDataIdentifier.name,
                          models.TemporaryDataIdentifier.path,
                          models.TemporaryDataIdentifier.bytes).\
        with_hint(models.TemporaryDataIdentifier, "INDEX(tmp_dids TMP_DIDS_EXPIRED_AT_IDX)", 'oracle').\
        filter(case([(models.TemporaryDataIdentifier.expired_at != is_none, models.TemporaryDataIdentifier.rse_id), ]) == rse_id)

    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='name')

    return [{'path': path,
             'rse_id': rse_id,
             'scope': scope,
             'name': name,
             'bytes': bytes}
            for scope, name, path, bytes in query.limit(limit)]


@transactional_session
def delete_temporary_dids(dids, session=None):
    """
    Delete temporary file replicas.

    :param dids: the list of files to delete.
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


@read_session
def get_count_of_expired_temporary_dids(rse_id, session=None):
    """
    List expired temporary DIDs.

    :param rse_id: the rse id.
    :param session: The database session in use.

    :returns: a count number.
    """
    is_none = None
    count = session.query(func.count(models.TemporaryDataIdentifier.scope)).\
        with_hint(models.TemporaryDataIdentifier, "INDEX(tmp_dids TMP_DIDS_EXPIRED_AT_IDX)", 'oracle').\
        filter(case([(models.TemporaryDataIdentifier.expired_at != is_none, models.TemporaryDataIdentifier.rse_id), ]) == rse_id).\
        one()

    return count[0] or 0
