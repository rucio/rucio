# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Ilija Vukotic <ivukotic@uchicago.edu>, 2021
#
# PY3K COMPATIBLE

from rucio.api import permission
from rucio.common import exception
from rucio.core import heartbeat


def list_heartbeats(issuer=None, vo='def'):
    """
    Return a list of tuples of all heartbeats.

    :param issuer: The issuer account.
    :param vo: the VO for the issuer.
    :returns: List of tuples [('Executable', 'Hostname', ...), ...]
    """

    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='list_heartbeats', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot list heartbeats' % issuer)
    return heartbeat.list_heartbeats()


def create_heartbeat(executable, hostname, pid, thread, older_than, payload, issuer=None, vo='def'):
    """
    Creates a heartbeat.
    :param issuer: The issuer account.
    :param vo: the VO for the issuer.
    :param executable: Executable name as a string, e.g., conveyor-submitter.
    :param hostname: Hostname as a string, e.g., rucio-daemon-prod-01.cern.ch.
    :param pid: UNIX Process ID as a number, e.g., 1234.
    :param thread: Python Thread Object.
    :param older_than: Ignore specified heartbeats older than specified nr of seconds.
    :param payload: Payload identifier which can be further used to identify the work a certain thread is executing.

    """
    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='send_heartbeats', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot send heartbeats' % issuer)
    heartbeat.live(executable=executable, hostname=hostname, pid=pid, thread=thread, older_than=older_than, payload=payload)
