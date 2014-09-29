# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from os import remove

import nose.tools
import re

from rucio import version
from rucio.common.config import config_get
from rucio.tests.common import execute, account_name_generator, rse_name_generator


class TestBinRucio():

    def setup(self):
        try:
            remove('/tmp/.rucio_root/auth_token_root')
        except OSError, e:
            if e.args[0] != 2:
                raise e
        self.marker = '$> '
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')

    def test_rucio_version(self):
        """CLI: Get Version"""
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal(err, 'rucio %s\n' % version.version_string())

    def test_rucio_ping(self):
        """PING (CLI): Rucio ping"""
        cmd = 'rucio --host %s ping' % self.host
        print self.marker + cmd
        exitcode, out, err = execute(cmd)

    def test_add_account(self):
        """ACCOUNT (CLI): Add account"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new account: %s\n' % tmp_val, out)

    def test_whoami(self):
        """ACCOUNT (CLI): Test whoami"""
        cmd = 'rucio whoami'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        nose.tools.assert_not_equal(re.search('.*account.*', out), None)

    def test_add_identity(self):
        """ACCOUNT (CLI): Test add identity"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal('Added new account: %s\n' % tmp_val, out)
        cmd = 'rucio-admin identity add --account %s --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new identity to account: jdoe@CERN.CH-%s\n' % tmp_val, out)

    def test_add_scope(self):
        """ACCOUNT (CLI): Test add identity"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin identity add --account %s --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new identity to account: jdoe@CERN.CH-%s\n' % tmp_val, out)

    def test_add_rse(self):
        """RSE (CLI): Add RSE"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new RSE: %s\n' % tmp_val, out)

    def test_list_rses(self):
        """RSE (CLI): List RSEs"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin rse list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print tmp_val
        nose.tools.assert_not_equal(re.search(tmp_val, out), None)

    def test_upload(self):
        """RSE (CLI): Upload"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio upload'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,

    def test_download(self):
        """RSE (CLI): Download"""
        cmd = 'rucio download'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
