# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013


def list_account_limits(account, rse_id, session=None):
    """
    Returns the quota limits for the account on the rse

    :param account:  Account to check the quota for
    :param rse_id:   RSE id to check the quota for
    :param session:  Database session in use
    :return:         Limit in Byte
    """
    # Mocking the Answer:
    return 1000000000000000000000


def list_account_usage(account, rse_id, session=None):
    """
    Returns the accounts space occupancy on the rse for the user

    :param account:  Account to check the quota for
    :param rse_id:   RSE id to check the quota for
    :param session:  Database session in use
    :return:         Usage in Byte
    """
    # Mocking the Answer:
    return 4
