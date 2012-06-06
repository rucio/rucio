# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

from uuid import uuid4 as uuid
from rucio.common import exception
from rucio.core.account import add_account
from rucio.core.inode import register_dataset, register_file


def create_tmp_dataset(scope, user, clean_list, monotonic=False):
    """ Registers a temporary dataset and puts it in a list to be cleaned """
    dsn = str(uuid())
    clean_list.append(dsn)
    register_dataset(scope, dsn, user, monotonic=monotonic)
    return dsn


def create_tmp_file(scope, user, clean_list):
    """ Registers a temporary file and puts it in a list to be cleaned """
    label = str(uuid())
    clean_list.append(label)
    register_file(scope, label, user)
    return label


def create_accounts(account_list, user_type):
    """ Registers a set of accounts """
    for account in account_list:
        try:
            add_account(account, user_type)
        except exception.Duplicate:
            pass  # Account already exists, no need to create it
