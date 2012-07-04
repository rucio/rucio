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
from re import compile
from nose.tools import *
from uuid import uuid4 as uuid

from rucio import version
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.tests.common import execute


class xTestBinRucio():

    def setUp(self):
        # sudo apachectl restart
        # build_database()
        # create_root_account()
        self.test_account = 'jdoe-' + str(uuid())
        self.test_location = 'MOCK-' + str(uuid())

    def tearDown(self):
        # sudo apachectl stop
        # destroy_database()
        pass

    def test_rucio_version(self):
        """CLI: Get Version"""
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        assert_equal(err, 'rucio %s\n' % version.version_string())

    def test_cli_add_list_delete_account(self):
        """ACCOUNT (CLI): Add/List/Delete account"""

        cmd = 'bin/rucio-admin --host=localhost  --port=443 --account=root \
               --user=ddmlab -pwd=secret --ca-certificate=etc/web/ca.crt  account add {self.test_account}'.format(self=self)
        exitcode, out, err = execute(cmd)
        assert_equal(out, '')
        assert_equal(exitcode, 0)

        cmd = 'bin/rucio-admin --host=localhost  --port=443 --account=root\
              --user=ddmlab -pwd=secret  --ca-certificate=etc/web/ca.crt  account list'.format(self=self)
        exitcode, out, err = execute(cmd)
        expected_regexp = '.*{self.test_account}.*'.format(self=self)
        result = compile(expected_regexp).search(out)
        assert_false(result == None, '%(expected_regexp)s Versus: %(out)s' % locals())
        assert_equal(exitcode, 0)

        cmd = 'bin/rucio-admin --host=localhost  --port=443 --account=root\
               --user=ddmlab -pwd=secret --ca-certificate=etc/web/ca.crt  account disable {self.test_account}'.format(self=self)
        exitcode, out, err = execute(cmd)
        assert_equal(out, '')
        assert_equal(exitcode, 0)

    def test_cli_add_list_delete_location(self):
        """LOCATION (CLI): Add/List location"""

        cmd = 'bin/rucio-admin --host=localhost  --port=443 --account=root\
             --user=ddmlab -pwd=secret --ca-certificate=etc/web/ca.crt  location add {self.test_location}'.format(self=self)
        exitcode, out, err = execute(cmd)
        assert_equal(out, '')
        assert_equal(exitcode, 0)

        cmd = 'bin/rucio-admin --host=localhost  --port=443 --account=root --user=ddmlab -pwd=secret --ca-certificate=etc/web/ca.crt  location list'.format(self=self)
        exitcode, out, err = execute(cmd)
        expected_regexp = '.*{self.test_location}.*'.format(self=self)
        result = compile(expected_regexp).search(out)
        assert_false(result == None, '%(expected_regexp)s Versus: %(out)s' % locals())
        assert_equal(exitcode, 0)
