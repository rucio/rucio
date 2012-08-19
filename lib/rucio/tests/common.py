# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from paste.fixture import TestApp
import subprocess
from uuid import uuid4 as uuid

from rucio.common import exception
from rucio.core.account import add_account
from rucio.core.name import register_dataset, register_file
from rucio.web.rest.authentication import app as auth_app


def execute(cmd):
    """
    Executes a command in a subprocess. Returns a tuple
    of (exitcode, out, err), where out is the string output
    from stdout and err is the string output from stderr when
    executing the command.

    :param cmd: Command string to execute
    """

    process = subprocess.Popen(cmd,
                               shell=True,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out = ''
    err = ''
    exitcode = 0

    result = process.communicate()
    (out, err) = result
    exitcode = process.returncode

    return exitcode, out, err


def create_tmp_dataset(scope, user, clean_list, monotonic=False):
    """ Registers a temporary dataset and puts it in a list to be cleaned

    :param scope: scope of the new dataset
    :param user: the account creating the dataset
    :param clean_list: the list where the name of dsn will be appended to
    :param monotonic: the monotic state of the new dataset
    :returns: the dataset name
    """
    dsn = str(uuid())
    clean_list.append(dsn)
    register_dataset(scope, dsn, user, monotonic=monotonic)
    return dsn


def create_tmp_file(scope, user, clean_list):
    """ Registers a temporary file and puts it in a list to be cleaned

    :param scope: the scope of the new file
    :param user: the account creating the dataset
    :param clean_list: the list where the name of the file will be appended to
    :returns: the filename
    """
    label = str(uuid())
    clean_list.append(label)
    register_file(scope, label, user)
    return label


def create_accounts(account_list, user_type):
    """ Registers a set of accounts

    :param account_list: the list of accounts to be added
    :param user_type: the type of accounts
    """
    for account in account_list:
        try:
            add_account(account, user_type)
        except exception.Duplicate:
            pass  # Account already exists, no need to create it


def get_auth_token(account, username, password):
    """ Get's an authentication token from the server

    :param account: the account authenticating
    :param username:the username linked to the account
    :param password: the password linked to the account
    :returns: the authentication token
    """
    mw = []
    header = {'Rucio-Account': account, 'Rucio-Username': username, 'Rucio-Password': password}
    r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=header, expect_errors=True)
    token = str(r1.header('Rucio-Auth-Token'))
    return token
