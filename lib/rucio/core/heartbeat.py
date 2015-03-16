# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

import datetime

from sqlalchemy.sql import distinct

from rucio.db.models import Heartbeats
from rucio.db.session import transactional_session
from rucio.common.utils import pid_exists


@transactional_session
def sanity_check(executable, hostname, session=None):
    """
    Check if processes on the host are still running.

    :param executable: Executable name as a string, e.g., conveyor-submitter
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch
    """
    for pid, in session.query(distinct(Heartbeats.pid)).filter_by(executable=executable, hostname=hostname):
        if not pid_exists(pid):
            session.query(Heartbeats).filter_by(executable=executable, hostname=hostname, pid=pid).delete()


@transactional_session
def live(executable, hostname, pid, thread, older_than=600, session=None):
    """
    Register a heartbeat for a process/thread on a given node.
    The executable name is used for the calculation of thread assignments.
    Removes all stale heartbeats for the given executable.

    TODO: Returns an assignment dictionary for the given executable.

    :param executable: Executable name as a string, e.g., conveyor-submitter
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch
    :param pid: UNIX Process ID as a number, e.g., 1234
    :param thread: Python Thread Object
    :param older_than: Removes specified heartbeats older than specified nr of seconds

    :returns heartbeats: Dictionary {assign_thread, nr_threads}
    """

    # first, delete the old ones (assume same executable, but different args)
    query = session.query(Heartbeats).filter(Heartbeats.executable.like('%s%%' % executable.split()[0]))
    if older_than:
        query = query.filter(Heartbeats.updated_at < datetime.datetime.utcnow()-datetime.timedelta(seconds=older_than))
    query.delete(synchronize_session=False)

    # upsert the heartbeat
    tmp_hb = Heartbeats(executable=executable,
                        hostname=hostname,
                        pid=pid,
                        thread_id=thread.ident,
                        thread_name=thread.name)
    tmp_hb = session.merge(tmp_hb)
    tmp_hb.save(session=session)

    # assign thread identifier
    query = session.query(Heartbeats.hostname,
                          Heartbeats.pid,
                          Heartbeats.thread_id)\
                   .filter(Heartbeats.executable.like('%s%%' % executable.split()[0]))\
                   .group_by(Heartbeats.executable,
                             Heartbeats.hostname,
                             Heartbeats.pid,
                             Heartbeats.thread_id)\
                   .order_by(Heartbeats.executable,
                             Heartbeats.hostname,
                             Heartbeats.pid,
                             Heartbeats.thread_id)
    result = query.all()

    # there is no universally applicable rownumber in SQLAlchemy
    # so we have to do it in Python
    assign_thread = None
    for r in xrange(len(result)):
        if result[r][0] == hostname and result[r][1] == pid and result[r][2] == thread.ident:
            assign_thread = r
            break

    return {'assign_thread': assign_thread,
            'nr_threads': len(result)}


@transactional_session
def die(executable, hostname, pid, thread, older_than=None, session=None):
    """
    Remove a single heartbeat older than specified.

    :param executable: Executable name as a string, e.g., conveyor-submitter
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch
    :param pid: UNIX Process ID as a number, e.g., 1234
    :param thread: Python Thread Object
    :param older_than: Removes specified heartbeats older than specified nr of seconds

    :returns heartbeats: Dictionary {assign_thread, nr_threads}
    """

    query = session.query(Heartbeats).filter_by(executable=executable,
                                                hostname=hostname,
                                                pid=pid,
                                                thread_id=thread.ident)

    if older_than:
        query = query.filter(Heartbeats.updated_at < datetime.datetime.utcnow()-datetime.timedelta(seconds=older_than))

    query.delete()


@transactional_session
def cardiac_arrest(older_than=None, session=None):
    """
    Removes all heartbeats older than specified.

    :param older_than: Removes all heartbeats older than specified nr of seconds
    """

    query = session.query(Heartbeats)

    if older_than:
        query = query.filter(Heartbeats.updated_at < datetime.datetime.utcnow()-datetime.timedelta(seconds=older_than))

    query.delete()
