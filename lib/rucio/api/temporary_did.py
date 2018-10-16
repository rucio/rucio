'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the
  License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016

  PY3K COMPATIBLE
'''

from rucio.core import temporary_did


def add_temporary_dids(dids, issuer):
    """
    Bulk add temporary data identifiers.

    :param dids: A list of dids.
    :param issuer: The issuer account.
    """
    return temporary_did.add_temporary_dids(dids=dids, account=issuer)
