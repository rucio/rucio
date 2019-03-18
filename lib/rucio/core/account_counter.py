# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2019
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import bindparam, text

from rucio.common.exception import CounterNotFound
import rucio.core.account
import rucio.core.rse

from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session

MAX_COUNTERS = 10


@transactional_session
def add_counter(rse_id, account, session=None):
    """
    Creates the specified counter for a rse_id and account.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param session: The database session in use
    """

    models.AccountUsage(rse_id=rse_id, account=account, files=0, bytes=0).save(session=session)


@transactional_session
def create_counters_for_new_account(account, session=None):
    """
    Creates all the Account counters when creating a account.

    :param account: The account.
    :param session: The database session in use.models.RSECounter
    """

    for rse_id in [rse['id'] for rse in rucio.core.rse.list_rses(session=session)]:
        add_counter(rse_id=rse_id, account=account, session=session)


@transactional_session
def create_counters_for_new_rse(rse_id, session=None):
    """
    Creates all the Account counters when creating a new rse.

    :param rse_id:  The rse_id.
    :param session: The database session in use.models.RSECounter
    """

    for account in rucio.core.account.list_accounts(session=session):
        add_counter(rse_id=rse_id, account=account['account'], session=session)


@transactional_session
def increase(rse_id, account, files, bytes, session=None):
    """
    Increments the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param files:   The number of added/removed files.
    :param bytes:   The corresponding amount in bytes.
    :param session: The database session in use.
    """

    models.UpdatedAccountCounter(account=account, rse_id=rse_id, files=files, bytes=bytes).save(session=session)


@transactional_session
def decrease(rse_id, account, files, bytes, session=None):
    """
    Decreases the specified counter by the specified amount.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param files:   The amount of files.
    :param bytes:   The amount of bytes.
    :param session: The database session in use.
    """

    return increase(rse_id=rse_id, account=account, files=-files, bytes=-bytes, session=session)


@transactional_session
def del_counter(rse_id, account, session=None):
    """
    Resets the specified counter and initializes it by the specified amounts.

    :param rse_id:  The id of the RSE.
    :param account: The account name.
    :param session: The database session in use.
    """

    session.query(models.AccountUsage).filter_by(rse_id=rse_id, account=account).delete(synchronize_session=False)


@read_session
def get_updated_account_counters(total_workers, worker_number, session=None):
    """
    Get updated rse_counters.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param session:            Database session in use.
    :returns:                  List of rse_ids whose rse_counters need to be updated.
    """
    query = session.query(models.UpdatedAccountCounter.account, models.UpdatedAccountCounter.rse_id).\
        distinct(models.UpdatedAccountCounter.account, models.UpdatedAccountCounter.rse_id)

    if total_workers > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number),
                          bindparam('total_workers', total_workers)]
            query = query.filter(text('ORA_HASH(CONCAT(account, rse_id), :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(concat(account, rse_id)), %s) = %s' % (total_workers + 1, worker_number))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(concat(account, rse_id)))::bit(32)::int), %s) = %s' % (total_workers + 1, worker_number))

    return query.all()


@transactional_session
def update_account_counter(account, rse_id, session=None):
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
def update_account_counter_history(account, rse_id, session=None):
    """
    Read the AccountUsage and update the AccountUsageHistory.

    :param account:  The account to update.
    :param rse_id:   The rse_id to update.
    :param session:  Database session in use.
    """
    AccountUsageHistory = models.AccountUsage.__history_mapper__.class_
    try:
        counter = session.query(models.AccountUsage).filter_by(rse_id=rse_id, account=account).one()
        AccountUsageHistory(rse_id=rse_id, account=account, files=counter.files, bytes=counter.bytes).save(session=session)
    except NoResultFound:
        raise CounterNotFound('No usage can be found for account %s on RSE with id %s' % (account, rse_id))


@transactional_session
def fill_account_counter_history_table(session=None):
    """
    Fill the account usage history table with the current usage.

    :param session:  Database session in use.
    """
    AccountUsageHistory = models.AccountUsage.__history_mapper__.class_
    for usage in session.query(models.AccountUsage).all():
        AccountUsageHistory(rse_id=usage['rse_id'], account=usage['account'], files=usage['files'], bytes=usage['bytes']).save(session=session)
