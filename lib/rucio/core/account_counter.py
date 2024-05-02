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
import datetime
from typing import TYPE_CHECKING

from sqlalchemy import insert, literal, select
from sqlalchemy.exc import NoResultFound

from rucio.db.sqla import filter_thread_work, models
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, RSEAccountCounterDict

MAX_COUNTERS = 10


@transactional_session
def add_counter(
    rse_id: str,
    account: "InternalAccount",
    *,
    session: "Session"
) -> None:
    """
    Creates the specified counter for a rse_id and account.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param session: The database session in use
    """

    models.AccountUsage(rse_id=rse_id, account=account, files=0, bytes=0).save(session=session)


@transactional_session
def increase(
    rse_id: str,
    account: "InternalAccount",
    files: int,
    bytes_: int,
    *,
    session: "Session"
) -> None:
    """
    Increments the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param files:   The number of added/removed files.
    :param bytes_:   The corresponding amount in bytes.
    :param session: The database session in use.
    """
    models.UpdatedAccountCounter(account=account, rse_id=rse_id, files=files, bytes=bytes_).save(session=session)


@transactional_session
def decrease(
    rse_id: str,
    account: "InternalAccount",
    files: int,
    bytes_: int,
    *,
    session: "Session"
) -> None:
    """
    Decreases the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param files:   The amount of files.
    :param bytes_:   The amount of bytes.
    :param session: The database session in use.
    """
    return increase(rse_id=rse_id, account=account, files=-files, bytes_=-bytes_, session=session)


@transactional_session
def del_counter(
    rse_id: str,
    account: "InternalAccount",
    *,
    session: "Session"
) -> None:
    """
    Resets the specified counter and initializes it by the specified amounts.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param session: The database session in use.
    """

    session.query(models.AccountUsage).filter_by(rse_id=rse_id, account=account).delete(synchronize_session=False)


@read_session
def get_updated_account_counters(
    total_workers: int,
    worker_number: int,
    *,
    session: "Session"
) -> list["RSEAccountCounterDict"]:
    """
    Get updated rse_counters.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param session:            Database session in use.
    :returns:                  List of rse_ids whose rse_counters need to be updated.
    """

    query = select(
        models.UpdatedAccountCounter.account,
        models.UpdatedAccountCounter.rse_id,
    ).distinct(
    )

    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='CONCAT(account, rse_id)')

    return [row._asdict() for row in session.execute(query).all()]  # type: ignore (pending SQLA2.1: https://github.com/rucio/rucio/discussions/6615)


@transactional_session
def update_account_counter(
    account: "InternalAccount",
    rse_id: str,
    *,
    session: "Session"
) -> None:
    """
    Read the updated_account_counters and update the account_counter.

    :param account:  The account to update.
    :param rse_id:   The rse_id to update.
    :param session:  Database session in use.
    """

    updated_account_counters = session.query(models.UpdatedAccountCounter).filter_by(account=account, rse_id=rse_id).all()

    try:
        account_counter = session.query(models.AccountUsage).filter_by(account=account, rse_id=rse_id).one()
        account_counter.bytes += sum([updated_account_counter.bytes for updated_account_counter in updated_account_counters])
        account_counter.files += sum([updated_account_counter.files for updated_account_counter in updated_account_counters])
    except NoResultFound:
        models.AccountUsage(rse_id=rse_id,
                            account=account,
                            files=sum([updated_account_counter.files for updated_account_counter in updated_account_counters]),
                            bytes=sum([updated_account_counter.bytes for updated_account_counter in updated_account_counters])).save(session=session)

    for update in updated_account_counters:
        update.delete(flush=False, session=session)


@transactional_session
def update_account_counter_history(
    account: "InternalAccount",
    rse_id: str,
    *,
    session: "Session"
) -> None:
    """
    Read the AccountUsage and update the AccountUsageHistory.

    :param account:  The account to update.
    :param rse_id:   The rse_id to update.
    :param session:  Database session in use.
    """
    counter = session.query(models.AccountUsage).filter_by(rse_id=rse_id, account=account).one_or_none()
    if counter:
        models.AccountUsageHistory(rse_id=rse_id, account=account, files=counter.files, bytes=counter.bytes).save(session=session)
    else:
        models.AccountUsageHistory(rse_id=rse_id, account=account, files=0, bytes=0).save(session=session)


@transactional_session
def fill_account_counter_history_table(*, session: "Session") -> None:
    """
    Make a snapshot of current counters

    :param session:  Database session in use.
    """

    select_counters_stmt = select(
        models.AccountUsage.rse_id,
        models.AccountUsage.account,
        models.AccountUsage.files,
        models.AccountUsage.bytes,
        literal(datetime.datetime.utcnow()),
    )

    stmt = insert(
        models.AccountUsageHistory
    ).from_select(
        ['rse_id', 'account', 'files', 'bytes', 'updated_at'],
        select_counters_stmt
    )
    session.execute(stmt)
