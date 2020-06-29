'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2016-2017
  - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019

  PY3K COMPATIBLE
'''

from rucio.api import permission
from rucio.core import lifetime_exception
from rucio.common import exception
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict


def list_exceptions(exception_id=None, states=None, vo='def'):
    """
    List exceptions to Lifetime Model.

    :param id:         The id of the exception
    :param states:     The states to filter
    :param vo:         The VO to act on
    """

    exceptions = lifetime_exception.list_exceptions(exception_id=exception_id, states=states)
    for e in exceptions:
        if vo == e['scope'].vo:
            yield api_update_return_dict(e)


def add_exception(dids, account, pattern, comments, expires_at, vo='def'):
    """
    Add exceptions to Lifetime Model.

    :param dids:        The list of dids
    :param account:     The account of the requester.
    :param pattern:     The account.
    :param comments:    The comments associated to the exception.
    :param expires_at:  The expiration date of the exception.
    :param vo:          The VO to act on.

    returns:            The id of the exception.
    """

    account = InternalAccount(account, vo=vo)
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)
    return lifetime_exception.add_exception(dids=dids, account=account, pattern=pattern, comments=comments, expires_at=expires_at)


def update_exception(exception_id, state, issuer, vo='def'):
    """
    Update exceptions state to Lifetime Model.

    :param id:         The id of the exception.
    :param state:      The states to filter.
    :param issuer:     The issuer account.
    :param vo:         The VO to act on.
    """
    kwargs = {'exception_id': exception_id, 'vo': vo}
    if not permission.has_permission(issuer=issuer, vo=vo, action='update_lifetime_exceptions', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update lifetime exceptions' % (issuer))
    return lifetime_exception.update_exception(exception_id=exception_id, state=state)
