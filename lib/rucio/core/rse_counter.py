# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import bindparam, text

from rucio.common.exception import CounterNotFound
from rucio.db import models
from rucio.db.session import read_session, transactional_session


@transactional_session
def add_counter(rse_id, session=None):
    """
    Creates the specified counter for a rse_id.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """

    models.RSECounter(rse_id=rse_id, files=0, bytes=0).save(session=session)


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

    session.query(models.RSECounter).filter_by(rse_id=rse_id).delete(synchronize_session=False)


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
        counter = session.query(models.RSECounter).filter_by(rse_id=rse_id).one()
        return {'bytes': counter.bytes, 'files': counter.files, 'updated_at':  counter.updated_at}
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

    if total_workers > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number),
                          bindparam('total_workers', total_workers)]
            query = query.filter(text('ORA_HASH(rse_id, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(rse_id), %s) = %s' % (total_workers, worker_number))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(rse_id))::bit(32)::int), %s) = %s' % (total_workers, worker_number))

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

    try:
        rse_counter = session.query(models.RSECounter).filter_by(rse_id=rse_id).one()
        rse_counter.bytes += sum([updated_rse_counter.bytes for updated_rse_counter in updated_rse_counters])
        rse_counter.files += sum([updated_rse_counter.files for updated_rse_counter in updated_rse_counters])
    except NoResultFound:
        pass

    for update in updated_rse_counters:
        update.delete(flush=False, session=session)
