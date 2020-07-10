'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the
  License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
  - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019

  PY3K COMPATIBLE
'''

from rucio.common.types import InternalAccount, InternalScope
from rucio.core import temporary_did
from rucio.core.rse import get_rse_id


def add_temporary_dids(dids, issuer, vo='def'):
    """
    Bulk add temporary data identifiers.

    :param dids: A list of dids.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    for did in dids:
        if 'rse' in did and 'rse_id' not in did:
            rse_id = None
            if did['rse'] is not None:
                rse_id = get_rse_id(rse=did['rse'], vo=vo)
            did['rse_id'] = rse_id
        if 'scope' in did:
            did['scope'] = InternalScope(did['scope'], vo=vo)
        if 'parent_scope' in did:
            did['parent_scope'] = InternalScope(did['parent_scope'], vo=vo)

    issuer = InternalAccount(issuer, vo=vo)
    return temporary_did.add_temporary_dids(dids=dids, account=issuer)
