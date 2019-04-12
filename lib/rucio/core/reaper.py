# Copyright 2012-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne, <vgaronne@gmail.com>, 2019

import datetime

from rucio.db.sqla.models import Heartbeats, RSE, RSEAttrAssociation, RSEUsage
from rucio.db.sqla.session import read_session

from sqlalchemy import or_
from sqlalchemy.orm import aliased
from sqlalchemy.sql.expression import bindparam, text

THREADS_PER_RSE = 10


@read_session
def get_thread_number(hostname, pid, thread_id, older_than=600, session=None):
    """
    Get thread number for reaper --auto.

    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch.
    :param pid: UNIX Process ID as a number, e.g., 1234.
    :param thread_id: Python Thread Id.
    :param older_than: Ignore specified heartbeats older than specified nr of seconds.
    :param session: The database session in use.

    :returns: a dictionary  {'total_threads': total_threads, 'thread_number': thread_number}
    """
    query = session.query(
        Heartbeats.hostname,
        Heartbeats.pid,
        Heartbeats.thread_id).\
        filter(Heartbeats.readable == 'rucio-reaper --auto').\
        filter(Heartbeats.updated_at >= datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than)).\
        order_by(Heartbeats.hostname,
                 Heartbeats.pid,
                 Heartbeats.thread_id)

    thread_number, total_threads = None, 0
    for row in query:
        if row == (hostname, pid, thread_id):
            thread_number = total_threads
        total_threads += 1

    return {'total_threads': total_threads,
            'thread_number': thread_number}


@read_session
def get_rse_thread_number(rse, total_threads, thread_number, session=None):
    """
    Get RSE thread number for a specific RSE.

    :param RSE: The RSE name.
    :param total_threads: The total number of threads for reaper --auto.
    :param thread_number: The thread number.
    :param session: The database session in use.

    :returns: a dictionary {'total_threads_per_rse': total_threads_per_rse, 'rse_thread_number': rse_thread_number}
    """

    if total_threads < THREADS_PER_RSE:
        concurrency = total_threads
    else:
        concurrency = THREADS_PER_RSE

    if session.bind.dialect.name == 'oracle':
        query = '''select n-1,ora_hash(id||(n-1), %s)
        from atlas_rucio.rses,
        (SELECT LEVEL n
        FROM DUAL
        CONNECT BY LEVEL <= %s)
        where rse='%s'
        order by n''' % (total_threads, concurrency, rse)
    else:
        raise NotImplementedError

    rse_thread_number, total_threads_per_rse = None, 0
    for row in session.execute(query):
        if row[1] == thread_number:
            rse_thread_number = total_threads_per_rse + 1
        total_threads_per_rse += 1

    return {'total_threads_per_rse': total_threads_per_rse,
            'rse_thread_number': rse_thread_number}


@read_session
def list_rses_for_thread(thread_number, total_threads, dynamic=True, session=None):
    """
    List RSES assigned dynacicaly to a reaper --auto thread.

    :param thread_number: The thread number.
    :param total_threads: The total number of threads for reaper --auto.
    :param dynamic: When True considers only the RSE with a deletion backlog.
    :param session: The database session in use.

    :returns: a list of RSES
    """
    false_value = False

    query = session.query(RSE.id, RSE.rse).\
        join(RSEAttrAssociation, RSE.id == RSEAttrAssociation.rse_id).\
        filter(RSE.deleted == false_value).\
        filter(RSEAttrAssociation.key == 'tombstone')

    query = session.query(RSE.id, RSE.rse).\
        filter(RSE.deleted == false_value)

    if dynamic:
        expired = aliased(RSEUsage)
        obsolete = aliased(RSEUsage)
        query = query.\
            join(expired, RSE.id == expired.rse_id).\
            filter(expired.source == 'expired').\
            filter(expired.files > 0).\
            join(obsolete, RSE.id == obsolete.rse_id).\
            filter(obsolete.source == 'obsolete').\
            filter(obsolete.files > 0)

    if total_threads < THREADS_PER_RSE:
        concurrency = total_threads
    else:
        concurrency = THREADS_PER_RSE

    condition = []
    for i in range(concurrency):
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_number', thread_number),
                          bindparam('total_threads', total_threads)]
            condition.append(text('ORA_HASH(id||%s, :total_threads) = :thread_number' % i, bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            condition.append(text('mod(md5(id||%s), %s) = %s' % (i, total_threads, thread_number)))
            raise NotImplementedError
        elif session.bind.dialect.name == 'postgresql':
            condition.append(text('mod(abs((\'x\'||md5(||%s))::bit(32)::int), %s) = %s' % (i, total_threads, thread_number)))
            raise NotImplementedError

    query = query.filter(or_(*condition))

    return [{'id': id, 'rse': rse} for id, rse in query]
