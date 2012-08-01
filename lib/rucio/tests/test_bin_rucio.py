# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

import nose.tools

from rucio import version
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.tests.common import execute


class TestBinRucio():

    def setUp(self):
        build_database(echo=False)
        create_root_account()
        self.marker = '$> '

    def tearDown(self):
        destroy_database(echo=False)

    def test_rucio_version(self):
        """CLI: Get Version"""
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal(err, 'rucio %s\n' % version.version_string())

    def test_rucio_ping(self):
        """PING (CLI): Rucio ping"""
        cmd = 'rucio ping'
        print  self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_in(version.version_string(), out)

    def test_add_account(self):
        """ACCOUNT (CLI): Add account"""
        cmd = 'rucio-admin --host=localhost --port=443 --account=root --user=ddmlab -pwd=secret --ca-certificate=etc/web/ca.crt account add jdoe user'
        print  self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new account: jdoe\n', out)
