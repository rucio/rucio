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

from sqlalchemy.orm.exc import NoResultFound

from rucio.common.exception import CounterNotFound
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_counter(rse_id, session=None):
    """
    Creates the specified counter for a rse_id.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """
    models.RSEUsage(rse_id=rse_id, source='rucio', files=0, used=0).\
        save(session=session)


@transactional_session
def increase(rse_id, files, bytes_, session=None):
    """
    Increments the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param files:   The number of added files.
    :param bytes_:   The number of added bytes.
    :param session: The database session in use.
    """
    models.UpdatedRSECounter(rse_id=rse_id, files=files, bytes=bytes_).\
        save(session=session)


@transactional_session
def decrease(rse_id, files, bytes_, session=None):
    """
    Decreases the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param files:   The number of removed files.
    :param bytes_:   The number of removed bytes.
    :param session: The database session in use.
    """
    return increase(rse_id=rse_id, files=-files, bytes_=-bytes_, session=session)


@transactional_session
def del_counter(rse_id, session=None):
    """
    Delete specified counter.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """

    session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').\
        delete(synchronize_session=False)


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
        counter = session.query(models.RSEUsage).\
            filter_by(rse_id=rse_id, source='rucio').one()
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
    query = session.query(models.UpdatedRSECounter.rse_id).\
        distinct(models.UpdatedRSECounter.rse_id)

    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='rse_id')
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
def fill_rse_counter_history_table(session=None):
    """
    Fill the RSE usage history table with the current usage.

    :param session: Database session in use.
    """
    RSEUsageHistory = models.RSEUsageHistory
    for usage in session.query(models.RSEUsage).all():
        RSEUsageHistory(rse_id=usage['rse_id'], used=usage['used'], files=usage['files'], source=usage['source']).save(session=session)
