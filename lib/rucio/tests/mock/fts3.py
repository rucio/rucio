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
"""


def list_all():
    """
    List all transfer jobs.

    :returns: List of dictionaries with job information
    """

    t = sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor().execute('SELECT * FROM transfers ORDER BY lastmodified DESC')
    return t.fetchall()


def submit(tinfo):
    """
    Create a new transfer job in state QUEUED.

    :param tinfo: The transfer job information, like source, destination.
    :returns: The transfer job id.
    """

    tid = str(uuid.uuid4())
    sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor().execute('INSERT INTO transfers(tid, timestart, lastmodified, state, tinfo) VALUES (?, datetime(\'now\'), datetime(\'now\'), \'QUEUED\', ?)', [tid, str(tinfo)])
    return {'job_id': tid}


def query(tid):
    """
    Query the transfer job information of a single job. Has a chance to progress the job from QUEUED to either DONE or FAILED.

    :param tid: The transfer job id.
    :returns: The transfer job information.
    """

    new_state = random.sample(sum([['FINISHED']*15, ['FAILED']*3, ['FINISHEDDIRTY']*2, ['ACTIVE']*80], []), 1)[0]

    sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor().execute('UPDATE transfers SET state=?, lastmodified=datetime(\'now\') WHERE tid=? AND (state == \'ACTIVE\' OR state == \'QUEUED\')', [new_state, tid])
    t = sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor().execute('SELECT state FROM transfers WHERE tid=?', [tid])
    tr = t.fetchone()[0]

    r = {'job_state': tr}

    if tr == u'FAILED' or tr == u'FINISHEDDIRTY':
        r['reason'] = 'Mock FTS decided to kill your transfer.'
        r['files'] = [{'source_surl': 'mock_src', 'dest_surl': 'mock_dest', 'reason': 'mock failure'}]

    return r


def cancel(tid):
    """
    Kills a transfer by setting its state to CANCELLED.

    :param tid: The transfer job id.
    """

    sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor().execute('UPDATE transfers SET lastmodified=datetime(\'now\'), state=\'CANCELLED\' WHERE tid=? AND state!=\'DONE\'', [tid])


# one time setup
sqlite3.connect('/tmp/mock-fts.db', isolation_level=None).cursor().execute('CREATE TABLE IF NOT EXISTS transfers (tid PRIMARY KEY, timestart, lastmodified, state, tinfo)')
