# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from paste.fixture import TestApp
from nose.tools import *

from rucio import version
from rucio.tests.common import execute


class TestBinRucio():

    def setUp(self):
        # setup http
        pass

    def tearDown(self):
        # teardown http
        pass

    # FIXME: Disabled for now
    def xtest_rucio_version(self):
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        assert_equal(err, 'rucio %s\n' % version.version_string())

    # FIXME: Disabled for now
    def xtest_cli_add_account(self):
        """ACCOUNT (CLI): Add account"""
        cmd = 'bin/rucio-admin --host=localhost  --port=80 --account=ddmlab --user=mlassnig -pwd=secret account add jdoe'
        exitcode, out, err = execute(cmd)
        assert_equal(out, '')
        assert_equal(exitcode, 0)

    # FIXME: Disabled for now
    def xtest_cli_disable_account(self):
        """ACCOUNT (CLI): Disable account"""
        cmd = 'bin/rucio-admin --host=localhost  --port=80 --account=ddmlab --user=mlassnig -pwd=secret  account disable jdoe'
        exitcode, out, err = execute(cmd)
        assert_equal(out, '')
        assert_equal(exitcode, 0)

    # FIXME: Disabled for now
    def xtest_cli_list_accounts(self):
        """ACCOUNT (CLI): List account"""
        cmd = 'bin/rucio-admin --host=localhost  --port=80 --account=ddmlab --user=mlassnig -pwd=secret  account list'
        exitcode, out, err = execute(cmd)
        assert_equal(out, 'jdoe\n')
        assert_equal(exitcode, 0)
