# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2016
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Brandon White, <bjwhite@fnal.gov>, 2019
# - Eric Vaandering <ewv@fnal.gov>, 2021

import datetime

from rucio.common.exception import CounterNotFound
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import OBSOLETE
from rucio.db.sqla.session import read_session, transactional_session
from sqlalchemy import func
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import null


@transactional_session
def add_counter(rse_id, session=None):
    """
    Creates the specified counter for a rse_id.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """
    models.RSEUsage(rse_id=rse_id, source='rucio', files=0, used=0).save(session=session)


@transactional_session
def increase(rse_id, files, bytes, session=None):
    """
    Increments the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param files:   The number of added files.
    :param bytes:   The number of added bytes.
    :param session: The database session in use.
    """
    models.UpdatedRSECounter(rse_id=rse_id, files=files, bytes=bytes).save(session=session)


@transactional_session
def decrease(rse_id, files, bytes, session=None):
    """
    Decreases the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param files:   The number of removed files.
    :param bytes:   The number of removed bytes.
    :param session: The database session in use.
    """
    return increase(rse_id=rse_id, files=-files, bytes=-bytes, session=session)


@transactional_session
def del_counter(rse_id, session=None):
    """
    Delete specified counter.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """

    session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').delete(synchronize_session=False)


@read_session
def get_counter(rse_id, session=None):
    """
    Returns current values of the specified counter or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param session:          The database session in use.
    :returns:                A dictionary with total and bytes.
    :raises CounterNotFound: If the counter does not exist.
    :returns:                A dictionary with total and bytes.
    """

    try:
        counter = session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').one()
        return {'bytes': counter.used,
                'files': counter.files,
                'updated_at': counter.updated_at}
    except NoResultFound:
        raise CounterNotFound()


@read_session
def get_updated_rse_counters(total_workers, worker_number, session=None):
    """
    Get updated rse_counters.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param session:            Database session in use.
    :returns:                  List of rse_ids whose rse_counters need to be updated.
    """
    query = session.query(models.UpdatedRSECounter.rse_id).distinct(models.UpdatedRSECounter.rse_id)

    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number,
                               hash_variable='rse_id')
    results = query.all()
    return [result.rse_id for result in results]


@transactional_session
def update_rse_counter(rse_id, session=None):
    """
    Read the updated_rse_counters and update the rse_counter.

    :param rse_id:   The rse_id to update.
    :param session:  Database session in use.
    """

    updated_rse_counters = session.query(models.UpdatedRSECounter).filter_by(rse_id=rse_id).all()
    sum_bytes = sum([updated_rse_counter.bytes for updated_rse_counter in updated_rse_counters])
    sum_files = sum([updated_rse_counter.files for updated_rse_counter in updated_rse_counters])

    try:
        rse_counter = session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').one()
        rse_counter.used += sum_bytes
        rse_counter.files += sum_files
    except NoResultFound:
        models.RSEUsage(rse_id=rse_id,
                        used=sum_bytes,
                        files=sum_files,
                        source='rucio').save(session=session)

    for update in updated_rse_counters:
        update.delete(flush=False, session=session)


@transactional_session
def update_replica_counts(rse_id, session=None):
    """
    Read the replica counts and update rse_usage.

    :param rse_id:   The rse_id to update.
    :param session:  Database session in use.
    """

    # Get the counds of obsolete and deletably (expired) files
    obsolete_files, obsolete_bytes = (session
                                      .query(func.count(), func.sum(models.RSEFileAssociation.bytes))
                                      .with_hint(models.RSEFileAssociation,
                                                 "INDEX_FFS(REPLICAS REPLICAS_TOMBSTONE_IDX)", 'oracle')
                                      .filter(models.RSEFileAssociation.rse_id == rse_id,
                                              models.RSEFileAssociation.tombstone != null(),
                                              models.RSEFileAssociation.tombstone == OBSOLETE)
                                      .one())
    deletable_files, deletable_bytes = (session
                                        .query(func.count(), func.sum(models.RSEFileAssociation.bytes))
                                        .with_hint(models.RSEFileAssociation,
                                                   "INDEX_FFS(REPLICAS REPLICAS_TOMBSTONE_IDX)", 'oracle')
                                        .filter(models.RSEFileAssociation.rse_id == rse_id,
                                                models.RSEFileAssociation.tombstone != null(),
                                                models.RSEFileAssociation.tombstone < datetime.datetime.now())
                                        .one())
    # Integerize them if no rows are returned
    if not deletable_files:
        deletable_files = 0
    if not obsolete_files:
        obsolete_files = 0

    # Merge (INSERT or UPDATE) the values
    # fill_rse_counter_history_table takes care of the history for all types
    deletable = models.RSEUsage(rse_id=rse_id, used=deletable_bytes, files=deletable_files, source='expired')
    session.merge(deletable)
    obsolete = models.RSEUsage(rse_id=rse_id, used=obsolete_bytes, files=obsolete_files, source='obsolete')
    session.merge(obsolete)


@transactional_session
def fill_rse_counter_history_table(session=None):
    """
    Fill the RSE usage history table with the current usage.

    :param session: Database session in use.
    """
    RSEUsageHistory = models.RSEUsage.__history_mapper__.class_
    for usage in session.query(models.RSEUsage).all():
        RSEUsageHistory(rse_id=usage['rse_id'], used=usage['used'],
                        files=usage['files'], source=usage['source']).save(session=session)
