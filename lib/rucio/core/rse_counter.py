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
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import and_, delete, select
from sqlalchemy.exc import NoResultFound

from rucio.common.exception import CounterNotFound
from rucio.db.sqla import filter_thread_work, models

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.orm import Session


def add_counter(
        rse_id: str,
        session: "Session"
) -> None:
    """
    Creates the specified counter for a rse_id.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """
    models.RSEUsage(rse_id=rse_id, source='rucio', files=0, used=0).\
        save(session=session)


def increase(
        rse_id: str,
        files: int,
        bytes_: int,
        session: "Session"
) -> None:
    """
    Increments the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param files:   The number of added files.
    :param bytes_:   The number of added bytes.
    :param session: The database session in use.
    """
    models.UpdatedRSECounter(rse_id=rse_id, files=files, bytes=bytes_).\
        save(session=session)


def decrease(
        rse_id: str,
        files: int,
        bytes_: int,
        session: "Session"
) -> None:
    """
    Decreases the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param files:   The number of removed files.
    :param bytes_:   The number of removed bytes.
    :param session: The database session in use.
    """
    return increase(rse_id=rse_id, files=-files, bytes_=-bytes_, session=session)


def del_counter(
        rse_id: str,
        session: "Session"
) -> None:
    """
    Delete specified counter.

    :param rse_id:  The id of the RSE.
    :param session: The database session in use.
    """

    stmt = delete(
        models.RSEUsage
    ).where(
        and_(models.RSEUsage.rse_id == rse_id,
             models.RSEUsage.source == 'rucio')
    ).execution_options(
        synchronize_session=False
    )
    session.execute(stmt)


def get_counter(
        rse_id: str,
        session: "Session"
) -> dict[str, Any]:
    """
    Returns current values of the specified counter or raises CounterNotFound if the counter does not exist.

    :param rse_id:           The id of the RSE.
    :param session:          The database session in use.
    :raises CounterNotFound: If the counter does not exist.
    :returns:                A dictionary with total and bytes.
    """

    try:
        stmt = select(
            models.RSEUsage.used,
            models.RSEUsage.files,
            models.RSEUsage.updated_at
        ).where(
            and_(models.RSEUsage.rse_id == rse_id,
                 models.RSEUsage.source == 'rucio')
        )
        usage_bytes, usage_files, usage_updated_at = session.execute(stmt).one()
        return {
            'bytes': usage_bytes,
            'files': usage_files,
            'updated_at': usage_updated_at
        }
    except NoResultFound:
        raise CounterNotFound()


def get_updated_rse_counters(
        total_workers: Optional[int],
        worker_number: Optional[int],
        session: "Session"
) -> "Sequence[str]":
    """
    Get updated rse_counters.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param session:            Database session in use.
    :returns:                  List of rse_ids whose rse_counters need to be updated.
    """
    stmt = select(
        models.UpdatedRSECounter.rse_id
    ).distinct(
    )

    stmt = filter_thread_work(session=session, query=stmt, total_threads=total_workers, thread_id=worker_number, hash_variable='rse_id')
    return session.execute(stmt).scalars().all()


def update_rse_counter(
        rse_id: str,
        session: "Session"
) -> None:
    """
    Read the updated_rse_counters and update the rse_counter.

    :param rse_id:   The rse_id to update.
    :param session:  Database session in use.
    """

    stmt = select(
        models.UpdatedRSECounter
    ).where(
        models.UpdatedRSECounter.rse_id == rse_id
    )
    updated_rse_counters = session.execute(stmt).scalars().all()
    sum_bytes = sum([updated_rse_counter.bytes for updated_rse_counter in updated_rse_counters])
    sum_files = sum([updated_rse_counter.files for updated_rse_counter in updated_rse_counters])

    try:
        stmt = select(
            models.RSEUsage
        ).where(
            and_(models.RSEUsage.rse_id == rse_id,
                 models.RSEUsage.source == 'rucio')
        )
        rse_counter = session.execute(stmt).scalar_one()
        rse_counter.used = (rse_counter.used or 0) + sum_bytes
        rse_counter.files = (rse_counter.files or 0) + sum_files
    except NoResultFound:
        models.RSEUsage(rse_id=rse_id,
                        used=sum_bytes,
                        files=sum_files,
                        source='rucio').save(session=session)

    for update in updated_rse_counters:
        update.delete(flush=False, session=session)


def fill_rse_counter_history_table(session: "Session") -> None:
    """
    Fill the RSE usage history table with the current usage.

    :param session: Database session in use.
    """
    stmt = select(
        models.RSEUsage
    )
    for usage in session.execute(stmt).scalars().all():
        models.RSEUsageHistory(rse_id=usage['rse_id'], used=usage['used'], files=usage['files'], source=usage['source']).save(session=session)
