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
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2014

from os import remove

import nose.tools
import re

from rucio import version
from rucio.common.config import config_get
from rucio.tests.common import execute, account_name_generator, rse_name_generator, file_generator


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
        self.user = 'mock'
        self.def_rse = 'MOCK4'

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
        print out,
        nose.tools.assert_regexp_matches(out, re.compile('.*account.*'))

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
        print out,
        nose.tools.assert_regexp_matches(out, re.compile('.*%s.*' % tmp_val))

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

    def test_upload_file(self):
        """UPLOAD (CLI): File"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        cmd = 'rucio upload --rse {0} --scope {1} --files {2} {3} {4}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_not_equal(re.search('Upload successfull', err), None)

    def test_create_dataset(self):
        """DATASET (CLI): creation"""
        tmp_name = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        cmd = 'rucio add-dataset ' + tmp_name
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search('Added ' + tmp_name, out), None)

    def test_add_files_to_dataset(self):
        """DATASET (CLI): add files"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_dataset = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} --files {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_file2)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # create dataset
        cmd = 'rucio add-dataset ' + tmp_dataset
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add files to dataset
        cmd = 'rucio add-files-to-dataset --to {0} mock:{1} mock:{2}'.format(tmp_dataset, tmp_file1[5:], tmp_file2[5:])  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # find the added files
        cmd = 'rucio list-files ' + tmp_dataset
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

    def test_download_file(self):
        """DATASET (CLI): download files"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} --files {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # download files
        cmd = 'rucio download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:])  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search('DID {0}:{1}'.format(self.user, tmp_file1[5:]), out), None)

    def test_download_dataset(self):
        """DATASET (CLI): download dataset"""
        tmp_file1 = file_generator()
        tmp_dataset = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} --files {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # create dataset
        cmd = 'rucio add-dataset ' + tmp_dataset
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add files to dataset
        cmd = 'rucio add-files-to-dataset --to {0} {1}:{2}'.format(tmp_dataset, self.user, tmp_file1[5:])  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # download dataset
        cmd = 'rucio download --dir /tmp {0}'.format(tmp_dataset)  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        search = 'Getting file {0}:{1}'.format(self.user, tmp_file1[5:])
        nose.tools.assert_not_equal(re.search(search, err), None)
        search = 'File validated'
        nose.tools.assert_not_equal(re.search(search, out), None)
        search = 'DID ' + tmp_dataset
        nose.tools.assert_not_equal(re.search(search, out), None)

    def test_create_rule(self):
        """DATASET (CLI): rule creation"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} --files {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rules
        cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        rule = out[:-1]  # triming new line character
        # check if rule exist for the file
        cmd = "rucio list-rules --did {0}:{1}".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search(rule, out), None)
