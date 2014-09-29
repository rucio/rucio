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
# - Joaquin Bogado <joaquin.bogado@cern.ch>, 2014

from paste.fixture import TestApp
from random import choice
from string import ascii_uppercase

import subprocess

from rucio.common import exception
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account
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


def account_name_generator():
    """ Generate random account name.

    :returns: A random account name
    """
    return 'jdoe-' + str(uuid()).lower()[:20]


def scope_name_generator():
    """ Generate random scope name.

    :returns: A random scope name
    """
    return 'mock_' + str(uuid()).lower()[:20]


def rse_name_generator(size=10):
    """ Generate random RSE name.

    :returns: A random RSE name
    """
    return 'MOCK_' + ''.join(choice(ascii_uppercase) for x in xrange(size))


def file_generator(size=2, namelen=10):
    """ Create a bogus file and returns it's name.
    :param size: size in bytes
    :returns: The name of the generated file.
    """
    fn = '/tmp/file_' + ''.join(choice(ascii_uppercase) for x in xrange(namelen))
    execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fn, size))
    return fn
