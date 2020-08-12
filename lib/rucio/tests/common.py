# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2018
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Fernando López <felopez@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import contextlib
import os
import subprocess
import tempfile
from random import choice
from string import ascii_uppercase

import pytest
from paste.fixture import TestApp
from six import PY3

from rucio.client.accountclient import AccountClient
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid as uuid

skip_rse_tests_with_accounts = pytest.mark.skipif(not os.path.exists('etc/rse-accounts.cfg'), reason='fails if no rse-accounts.cfg found')


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

    return exitcode, out.decode(), err.decode()


def create_accounts(account_list, user_type):
    """ Registers a set of accounts

    :param account_list: the list of accounts to be added
    :param user_type: the type of accounts
    """
    account_client = AccountClient()
    for account in account_list:
        try:
            account_client.add_account(account, user_type, email=None)
        except exception.Duplicate:
            pass  # Account already exists, no need to create it


def get_auth_token(account, username, password):
    """ Get's an authentication token from the server

    :param account: the account authenticating
    :param username:the username linked to the account
    :param password: the password linked to the account
    :returns: the authentication token
    """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo_header = {'X-Rucio-VO': config_get('client', 'vo', raise_exception=False, default='tst')}
    else:
        vo_header = {}

    from rucio.web.rest.authentication import APP as auth_app
    mw = []
    header = {'Rucio-Account': account, 'Rucio-Username': username, 'Rucio-Password': password}
    header.update(vo_header)
    r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=header, expect_errors=True)
    token = str(r1.header('Rucio-Auth-Token'))
    return token


def account_name_generator():
    """ Generate random account name.

    :returns: A random account name
    """
    return 'jdoe-' + str(uuid()).lower()[:16]


def scope_name_generator():
    """ Generate random scope name.

    :returns: A random scope name
    """
    return 'mock_' + str(uuid()).lower()[:16]


def rse_name_generator(size=10):
    """ Generate random RSE name.

    :returns: A random RSE name
    """
    return 'MOCK_' + ''.join(choice(ascii_uppercase) for x in range(size))


def file_generator(size=2, namelen=10):
    """ Create a bogus file and returns it's name.
    :param size: size in bytes
    :returns: The name of the generated file.
    """
    fn = '/tmp/file_' + ''.join(choice(ascii_uppercase) for x in range(namelen))
    execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fn, size))
    return fn


def make_temp_file(dir, data):
    """
    Creates a temporal file and write `data` on it.
    :param data: String to be writen on the created file.
    :returns: Name of the temporal file.
    """
    fd, path = tempfile.mkstemp(dir=dir)
    if PY3:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(data)
    else:
        with os.fdopen(fd, 'w') as f:
            f.write(data)
    return path


@contextlib.contextmanager
def mock_open(module, file_like_object):
    call_info = {}

    def mocked_open(filename, mode='r'):
        call_info['filename'] = filename
        call_info['mode'] = mode
        file_like_object.close = lambda: None
        return contextlib.closing(file_like_object)

    setattr(module, 'open', mocked_open)
    try:
        yield call_info
    finally:
        file_like_object.seek(0)
        delattr(module, 'open')
