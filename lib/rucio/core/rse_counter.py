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

from random import randint

from sqlalchemy import func

from rucio.db import models
from rucio.db.session import read_session, transactional_session

MAX_COUNTERS = 1000


@transactional_session
def add_counter(rse_id, session=None):
    """
    Creates the specified counter for a rse_id.

    :param rse_id: The id of the RSE.
    :param session: The database session in use.
    """
    for num in xrange(MAX_COUNTERS):
        new_counter = models.RSECounter(rse_id=rse_id, num=num, files=0, bytes=0)

        # need to merge into the session, not save
        # otherwise PK will raise integrity errors on delayed writes
        session.merge(new_counter)


@transactional_session
def increase(rse_id, delta, bytes, session=None):
    """
    Increments the specified counter by the specified amount.

    :param rse_id: The id of the RSE.
    :param delta: The number of added/removed files.
    :param bytes: The corresponding amount in bytes.
    :param session: The database session in use.

    :returns: The numbers of affected rows.
    """
    num = randint(0, MAX_COUNTERS - 1)  # to avoid row lock contention
    rowcount = session.query(models.RSECounter).filter_by(rse_id=rse_id, num=num).\
        update({'files': models.RSECounter.files + delta, 'bytes': models.RSECounter.bytes + bytes})
    return rowcount


@transactional_session
def decrease(rse_id, delta, bytes, session=None):
    """
    Decreases the specified counter by the specified amount.

    :param rse_id: The id of the RSE.
    :param delta: the amount of bytes.
    :param session: The database session in use.
    """
    return increase(rse_id=rse_id, delta=-delta, bytes=-bytes, session=session)


@transactional_session
def del_counter(rse_id, session=None):
    """
    Resets the specified counter and initializes it by the specified amounts.

    :param rse_id: The id of the RSE.
    :param total: the total number of files.
    :param bytes: the amount of bytes.
    :param session: The database session in use.
    """
    rows = session.query(models.RSECounter).filter_by(rse_id=rse_id).with_lockmode('update').all()
    for row in rows:
        row.delete(flush=False, session=session)


@read_session
def get_counter(rse_id, session=None):
    """
    Returns current values of the specified counter, or 0,0 if the counter does not exist.

    :param rse_id: The id of the RSE.
    :param session: The database session in use.

    :returns: A dictionary with total and bytes.
    """
    files, bytes, updated_at = session.query(func.sum(models.RSECounter.files),
                                             func.sum(models.RSECounter.bytes),
                                             func.max(models.RSECounter.updated_at)).filter_by(rse_id=rse_id).one()
    return {'bytes': bytes or 0, 'files': files or 0, 'updated_at':  updated_at}
