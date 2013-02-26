# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import random
import sqlite3
import uuid

"""
This mock FTS3 server provides basic job control, with a random job progression model:
80% chance of staying queued, 15% chance of completion, 5% chance of failure.
"""


def __db():
    """
    Internal database handler.

    :returns: SQLite3 cursor object
    """

    return sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor()


def list_all():
    """
    List all transfer jobs.

    :returns: List of dictionaries with job information
    """

    t = __db().execute('SELECT * FROM transfers ORDER BY lastmodified DESC')
    return t.fetchall()


def submit(tinfo):
    """
    Create a new transfer job in state QUEUED.

    :param tinfo: The transfer job information, like source, destination.
    :returns: The transfer job id.
    """

    tid = str(uuid.uuid4())
    __db().execute('INSERT INTO transfers(tid, timestart, lastmodified, state, tinfo) VALUES (?, datetime(\'now\'), datetime(\'now\'), \'QUEUED\', ?)', [tid, str(tinfo)])
    return tid


def query(tid):
    """
    Query the transfer job information of a single job. Has a chance to progress the job from QUEUED to either DONE or FAILED.

    :param tid: The transfer job id.
    :returns: The transfer job information.
    """

    new_state = random.sample(sum([['DONE']*15, ['FAILED']*5, ['QUEUED']*80], []), 1)[0]
    __db().execute('UPDATE transfers SET state=?, lastmodified=datetime(\'now\') WHERE tid=? AND state == \'QUEUED\'', [new_state, tid])
    t = __db().execute('SELECT * FROM transfers WHERE tid=?', [tid])
    return t.fetchone()


def cancel(tid):
    """
    Kills a transfer by setting its state to CANCELLED.

    :param tid: The transfer job id.
    """

    __db().execute('UPDATE transfers SET lastmodified=datetime(\'now\'), state=\'CANCELLED\' WHERE tid=? AND state!=\'DONE\'', [tid])


# One time setup
__db().execute('CREATE TABLE IF NOT EXISTS transfers (tid PRIMARY KEY, timestart, lastmodified, state, tinfo)')
