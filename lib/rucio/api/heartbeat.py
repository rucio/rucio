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
