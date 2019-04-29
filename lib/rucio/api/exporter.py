'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
  - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019

  PY3K COMPATIBLE
'''

from rucio.api import permission
from rucio.common import exception
from rucio.core import exporter
from rucio.core.rse import get_rse_name


def export_data(issuer):
    """
    Export data from Rucio.

    :param issuer: the issuer.
    """
    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, action='export', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not export data' % issuer)

    data = exporter.export_data()
    distances = {}
    for src_id, tmp in data['distances']:
        src = get_rse_name(rse_id=src_id)
        distances[src_id] = {}
        for dst_id, dists in tmp:
            dst = get_rse_name(rse_id=dst_id)
            distances[src][dst] = dists
    data['distances'] = distances
    return data
