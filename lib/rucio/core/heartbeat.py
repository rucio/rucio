# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

import datetime
import hashlib

from sqlalchemy.sql import distinct

from rucio.db.sqla.models import Heartbeats
from rucio.db.sqla.session import read_session, transactional_session
from rucio.common.exception import DatabaseException
from rucio.common.utils import pid_exists


@transactional_session
def sanity_check(executable, hostname, hash_executable=None, pid=None, thread=None,
                 session=None):
    """
    sanity_check wrapper to ignore DatabaseException errors.

    :param executable: Executable name as a string, e.g., conveyor-submitter.
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch.
    :param hash_executable: Hash of the executable.
    :param pid: UNIX Process ID as a number, e.g., 1234.
    :param thread: Python Thread Object.

    :param session: The database session in use.
    """
    try:
        _sanity_check(executable=executable, hostname=hostname,
                      hash_executable=hash_executable, session=session)
        if pid:
            live(executable=executable, hostname=hostname,
                 pid=pid, thread=thread, session=session)
    except DatabaseException:
        pass


@transactional_session
def _sanity_check(executable, hostname, hash_executable=None, session=None):
    """
    Check if processes on the host are still running.

    :param executable: Executable name as a string, e.g., conveyor-submitter.
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch.
    :param hash_executable: Hash of the executable.
    """
    if executable:
        if not hash_executable:
            hash_executable = calc_hash(executable)

        for pid, in session.query(distinct(Heartbeats.pid)).filter_by(executable=hash_executable, hostname=hostname):
            if not pid_exists(pid):
                session.query(Heartbeats).filter_by(executable=hash_executable, hostname=hostname, pid=pid).delete()
    else:
        for pid, in session.query(distinct(Heartbeats.pid)).filter_by(hostname=hostname):
            if not pid_exists(pid):
                session.query(Heartbeats).filter_by(hostname=hostname, pid=pid).delete()


@transactional_session
def live(executable, hostname, pid, thread, older_than=600, hash_executable=None, session=None):
    """
    Register a heartbeat for a process/thread on a given node.
    The executable name is used for the calculation of thread assignments.
    Removal of stale heartbeats is done as a scheduled database job.

    TODO: Returns an assignment dictionary for the given executable.

    :param executable: Executable name as a string, e.g., conveyor-submitter.
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch.
    :param pid: UNIX Process ID as a number, e.g., 1234.
    :param thread: Python Thread Object.
    :param older_than: Ignore specified heartbeats older than specified nr of seconds.
    :param hash_executable: Hash of the executable.

    :returns heartbeats: Dictionary {assign_thread, nr_threads}
    """
    if not hash_executable:
        hash_executable = calc_hash(executable)

    # upsert the heartbeat
    rowcount = session.query(Heartbeats)\
        .filter_by(executable=hash_executable,
                   hostname=hostname,
                   pid=pid,
                   thread_id=thread.ident)\
        .update({'updated_at': datetime.datetime.utcnow()})
    if not rowcount:
        Heartbeats(executable=hash_executable,
                   readable=executable,
                   hostname=hostname,
                   pid=pid,
                   thread_id=thread.ident,
                   thread_name=thread.name).save(session=session)

    # assign thread identifier
    query = session.query(Heartbeats.hostname,
                          Heartbeats.pid,
                          Heartbeats.thread_id)\
                   .with_hint(Heartbeats, "index(HEARTBEATS HEARTBEATS_PK)", 'oracle')\
                   .filter(Heartbeats.executable == hash_executable)\
                   .filter(Heartbeats.updated_at >= datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than))\
                   .group_by(Heartbeats.hostname,
                             Heartbeats.pid,
                             Heartbeats.thread_id)\
                   .order_by(Heartbeats.hostname,
                             Heartbeats.pid,
                             Heartbeats.thread_id)
    result = query.all()

    # there is no universally applicable rownumber in SQLAlchemy
    # so we have to do it in Python
    assign_thread = 0
    for r in range(len(result)):
        if result[r][0] == hostname and result[r][1] == pid and result[r][2] == thread.ident:
            assign_thread = r
            break

    return {'assign_thread': assign_thread,
            'nr_threads': len(result)}


@transactional_session
def die(executable, hostname, pid, thread, older_than=None, hash_executable=None, session=None):
    """
    Remove a single heartbeat older than specified.

    :param executable: Executable name as a string, e.g., conveyor-submitter
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch
    :param pid: UNIX Process ID as a number, e.g., 1234
    :param thread: Python Thread Object
    :param older_than: Removes specified heartbeats older than specified nr of seconds
    :param hash_executable: Hash of the executable.

    :returns heartbeats: Dictionary {assign_thread, nr_threads}
    """
    if not hash_executable:
        hash_executable = calc_hash(executable)

    query = session.query(Heartbeats).filter_by(executable=hash_executable,
                                                hostname=hostname,
                                                pid=pid,
                                                thread_id=thread.ident)

    if older_than:
        query = query.filter(Heartbeats.updated_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than))

    query.delete()


@transactional_session
def cardiac_arrest(older_than=None, session=None):
    """
    Removes all heartbeats older than specified.

    :param older_than: Removes all heartbeats older than specified nr of seconds
    """

    query = session.query(Heartbeats)

    if older_than:
        query = query.filter(Heartbeats.updated_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than))

    query.delete()


@read_session
def list_heartbeats(session=None):
    """
    List all heartbeats.

    :returns: List of tuples
    """

    query = session.query(Heartbeats.readable,
                          Heartbeats.hostname,
                          Heartbeats.pid,
                          Heartbeats.thread_name,
                          Heartbeats.updated_at,
                          Heartbeats.created_at).order_by(Heartbeats.readable,
                                                          Heartbeats.hostname,
                                                          Heartbeats.thread_name)

    return query.all()


def calc_hash(executable):
    """
    Calculates a SHA256 hash.

    return: String of hexadecimal hash
    """
    return hashlib.sha256(executable.encode('utf-8')).hexdigest()
