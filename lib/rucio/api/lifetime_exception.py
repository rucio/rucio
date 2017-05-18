'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2016-2017
'''

from rucio.api import permission
from rucio.core import lifetime_exception
from rucio.common import exception


def list_exceptions(exception_id=None, states=None):
    """
    List exceptions to Lifetime Model.

    :param id:         The id of the exception
    :param states:     The states to filter
    """

    return lifetime_exception.list_exceptions(exception_id=exception_id, states=states)


def add_exception(dids, account, pattern, comments, expires_at):
    """
    Add exceptions to Lifetime Model.

    :param dids:        The list of dids
    :param account:     The account of the requester.
    :param pattern:     The account.
    :param comments:    The comments associated to the exception.
    :param expires_at:  The expiration date of the exception.

    returns:            The id of the exception.
    """
    return lifetime_exception.add_exception(dids=dids, account=account, pattern=pattern, comments=comments, expires_at=expires_at)


def update_exception(exception_id, state, issuer):
    """
    Update exceptions state to Lifetime Model.

    :param id:         The id of the exception.
    :param state:      The states to filter.
    :param issuer:     The issuer account.
    """
    kwargs = {}
    if not permission.has_permission(issuer=issuer, action='update_lifetime_exceptions', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not update lifetime exceptions' % (issuer))
    return lifetime_exception.update_exception(exception_id=exception_id, state=state)
