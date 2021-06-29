# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2021
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2018
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Fernando López <felopez@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

from __future__ import print_function

import contextlib
import itertools
import json
import os
import tempfile
from random import choice
from string import ascii_uppercase

import pytest
from six import PY3

from rucio.common.config import config_get, config_get_bool, get_config_dirs
from rucio.common.utils import generate_uuid as uuid, execute

skip_rse_tests_with_accounts = pytest.mark.skipif(not any(os.path.exists(os.path.join(d, 'rse-accounts.cfg')) for d in get_config_dirs()),
                                                  reason='fails if no rse-accounts.cfg found')
skiplimitedsql = pytest.mark.skipif('RDBMS' in os.environ and os.environ['RDBMS'] == 'sqlite',
                                    reason="does not work in SQLite because of missing features")


def get_long_vo():
    """ Get the VO name from the config file for testing.
    Don't map the name to a short version.
    :returns: VO name string.
    """
    vo_name = 'def'
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo_name = config_get('client', 'vo', raise_exception=False, default=None)
    return vo_name


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


def print_response(rest_response):
    print('Status:', rest_response.status)
    print()
    nohdrs = True
    for hdr, val in rest_response.headers.items():
        if nohdrs:
            print('Headers:')
            print('-------')
            nohdrs = False
        print('%s: %s' % (hdr, val))

    if not nohdrs:
        print()

    text = rest_response.get_data(as_text=True)
    print(text if text else '<no content>')


def headers(*iterables):
    return list(itertools.chain(*iterables))


def loginhdr(account, username, password):
    yield 'X-Rucio-Account', str(account)
    yield 'X-Rucio-Username', str(username)
    yield 'X-Rucio-Password', str(password)


def auth(token):
    yield 'X-Rucio-Auth-Token', str(token)


def vohdr(vo):
    if vo:
        yield 'X-Rucio-VO', str(vo)


def hdrdict(dictionary):
    for key in dictionary:
        yield str(key), str(dictionary[key])


def accept(mimetype):
    yield 'Accept', mimetype


class Mime:
    """ Enum-type class for mimetypes. """
    METALINK = 'application/metalink4+xml'
    JSON = 'application/json'
    JSON_STREAM = 'application/x-json-stream'
    BINARY = 'application/octet-stream'


def load_test_conf_file(file_name):
    config_dir = next(filter(lambda d: os.path.exists(os.path.join(d, file_name)), get_config_dirs()))
    with open(os.path.join(config_dir, file_name)) as f:
        return json.load(f)
