'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018

  PY3K COMPATIBLE
'''

from rucio.api import permission
from rucio.common import exception
from rucio.core import exporter


def export_data(issuer):
    """
    Export data from Rucio.

    :param issuer: the issuer.
    """
    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, action='export', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not export data' % issuer)

    return exporter.export_data()
