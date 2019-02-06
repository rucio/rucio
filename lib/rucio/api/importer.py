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
from rucio.common.schema import validate_schema
from rucio.core import importer


def import_data(data, issuer):
    """
    Import data to add/update/delete records in Rucio.

    :param data: data to be imported.
    :param issuer: the issuer.
    """
    kwargs = {'issuer': issuer}
    validate_schema(name='import', obj=data)
    if not permission.has_permission(issuer=issuer, action='import', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not import data' % issuer)

    return importer.import_data(data)
