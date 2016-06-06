'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013, 2016
  - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
  - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
  - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2014-2015
  - Cheng-Hsi Chao, <cheng-hsi.chao@cern.ch>, 2014
  - Martin Barisits, <martin.barisits@cern.ch>, 2015
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
'''

from os import remove, unlink, listdir, rmdir

import nose.tools
import re

from rucio import version
from rucio.common.config import config_get
from rucio.common.utils import generate_uuid
from rucio.core.account_limit import set_account_limit
from rucio.core.rse import get_rse_id
from rucio.tests.common import execute, account_name_generator, rse_name_generator, file_generator, scope_name_generator


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
        self.user = 'data13_hip'
        self.def_rse = 'MOCK4'

        set_account_limit('root', get_rse_id(self.def_rse), -1)

    def test_rucio_version(self):
        """CLIENT(USER): Rucio version"""
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal(err, 'rucio %s\n' % version.version_string())

    def test_rucio_ping(self):
        """CLIENT(USER): Rucio ping"""
        cmd = 'rucio --host %s ping' % self.host
        print self.marker + cmd
        exitcode, out, err = execute(cmd)

    def test_add_account(self):
        """CLIENT(ADMIN): Add account"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new account: %s\n' % tmp_val, out)

    def test_whoami(self):
        """CLIENT(USER): Rucio whoami"""
        cmd = 'rucio whoami'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_regexp_matches(out, re.compile('.*account.*'))

    def test_add_identity(self):
        """CLIENT(ADMIN): Add identity"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal('Added new account: %s\n' % tmp_val, out)
        cmd = 'rucio-admin identity add --account %s --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new identity to account: jdoe@CERN.CH-%s\n' % tmp_val, out)

    def test_del_identity(self):
        """CLIENT(ADMIN): Test del identity"""
        tmp_acc = account_name_generator()

        # create account
        cmd = 'rucio-admin account add %s' % tmp_acc
        exitcode, out, err = execute(cmd)
        # add identity to account
        cmd = 'rucio-admin identity add --account %s --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH' % tmp_acc
        exitcode, out, err = execute(cmd)
        # delete identity from account
        cmd = 'rucio-admin identity delete --account %s --type GSS --id jdoe@CERN.CH' % tmp_acc
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal('Deleted identity: jdoe@CERN.CH\n', out)
        # list identities for account
        cmd = 'rucio-admin account list-identities %s' % (tmp_acc)
        print self.marker + cmd
        print cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal('', out)

    def test_attributes(self):
        """CLIENT(ADMIN): Add/List/Delete attributes"""
        tmp_acc = account_name_generator()

        # create account
        cmd = 'rucio-admin account add %s' % tmp_acc
        exitcode, out, err = execute(cmd)
        # add attribute to the account
        cmd = 'rucio-admin account add-attribute {0} --key test_attribute_key --value true'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_equal(0, exitcode)
        # list attributes
        cmd = 'rucio-admin account list-attributes {0}'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_equal(0, exitcode)
        # delete attribute to the account
        cmd = 'rucio-admin account delete-attribute {0} --key test_attribute_key'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_equal(0, exitcode)

    def test_add_scope(self):
        """CLIENT(ADMIN): Add scope"""
        tmp_scp = scope_name_generator()
        tmp_acc = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_acc
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin scope add --account %s --scope %s' % (tmp_acc, tmp_scp)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal('Added new scope to account: %s-%s\n' % (tmp_scp, tmp_acc), out)

    def test_add_rse(self):
        """CLIENT(ADMIN): Add RSE"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_equal('Added new RSE: %s\n' % tmp_val, out)

    def test_list_rses(self):
        """CLIENT(ADMIN): List RSEs"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin rse list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_regexp_matches(out, re.compile('.*%s.*' % tmp_val))

    def test_upload(self):
        """CLIENT(USER): Upload"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio upload'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,

    def test_download(self):
        """CLIENT(USER): Download"""
        cmd = 'rucio download'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,

    def test_upload_file(self):
        """CLIENT(USER): Rucio upload files"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_not_equal(re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out), None)

    def test_upload_file_guid(self):
        """CLIENT(USER): Rucio upload file with guid"""
        tmp_file1 = file_generator()
        tmp_guid = generate_uuid()
        cmd = 'rucio upload --rse {0} --guid {1} --scope {2} {3}'.format(self.def_rse, tmp_guid, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        nose.tools.assert_not_equal(re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out), None)

    def test_upload_repeated_file(self):
        """CLIENT(USER): Rucio upload repeated files"""
        # One of the files to upload is already catalogued but was removed
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # get the rule for the file
        cmd = "rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        rule = out
        # delete the file from the catalog
        cmd = "rucio delete-rule {0}".format(rule)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # delete the fisical file
        cmd = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_not_equal(re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file2[5:]), out), None)

    def test_upload_repeated_file_dataset(self):
        """CLIENT(USER): Rucio upload repeated files to dataset"""
        # One of the files to upload is already in the dataset
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # upload the files to the dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # tmp_file1 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file1[5:]), out), None)
        # tmp_file3 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file3[5:]), out), None)

    def test_upload_file_dataset(self):
        """CLIENT(USER): Rucio upload files to dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file1[5:]), out), None)

    def test_create_dataset(self):
        """CLIENT(USER): Rucio add dataset"""
        tmp_name = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        cmd = 'rucio add-dataset ' + tmp_name
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search('Added ' + tmp_name, out), None)

    def test_add_files_to_dataset(self):
        """CLIENT(USER): Rucio add files to dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_dataset = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_file2)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # create dataset
        cmd = 'rucio add-dataset ' + tmp_dataset
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add files to dataset
        cmd = 'rucio attach {0} {3}:{1} {3}:{2}'.format(tmp_dataset, tmp_file1[5:], tmp_file2[5:], self.user)  # triming '/tmp/' from filename
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
        """CLIENT(USER): Rucio download files"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # download files
        cmd = 'rucio download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:])  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)
        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except:
            pass

    def test_download_dataset(self):
        """CLIENT(USER): Rucio download dataset"""
        tmp_file1 = file_generator()
        tmp_dataset = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # create dataset
        cmd = 'rucio add-dataset ' + tmp_dataset
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add files to dataset
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dataset, self.user, tmp_file1[5:])  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # download dataset
        cmd = 'rucio download --dir /tmp {0}'.format(tmp_dataset)  # triming '/tmp/' from filename
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        search = '{0} successfully downloaded'.format(tmp_file1[5:])  # triming '/tmp/' from filename
        nose.tools.assert_not_equal(re.search(search, err), None)

    def test_create_rule(self):
        """CLIENT(USER): Rucio add rule"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        # add quota
        set_account_limit('root', get_rse_id(tmp_rse), -1)
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
        # add quota
        set_account_limit('root', get_rse_id(tmp_rse), -1)
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
        # add quota
        set_account_limit('root', get_rse_id(tmp_rse), -1)
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
        cmd = "rucio list-rules {0}:{1}".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_not_equal(re.search(rule, out), None)

    def test_delete_rule(self):
        """CLIENT(USER): rule deletion"""
        set_account_limit('root', get_rse_id(self.def_rse), -1)
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        set_account_limit('root', get_rse_id(tmp_rse), -1)

        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add rules
        cmd = "rucio add-rule {0}:{1} 1 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print err
        print out
        # get the rules for the file
        cmd = "rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        (rule1, rule2) = out.split()
        # delete the rules for the file
        cmd = "rucio delete-rule {0}".format(rule1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        cmd = "rucio delete-rule {0}".format(rule2)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # search for the file
        cmd = "rucio list-dids {0}:{1}".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal(5, len(out.splitlines()))

    def test_add_file_twice(self):
        """CLIENT(USER): Add file twice"""
        tmp_file1 = file_generator()
        # add file twice
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal(re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out), None)

    def test_add_delete_add_file(self):
        """CLIENT(USER): Add/Delete/Add"""
        tmp_file1 = file_generator()
        # add file
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # get the rule for the file
        cmd = "rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        rule = out
        # delete the file from the catalog
        cmd = "rucio delete-rule {0}".format(rule)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # delete the fisical file
        cmd = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(tmp_file1[5:])
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # modify the file to avoid same checksum
        cmd = "echo 'delta' >> {0}".format(tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        # add the same file
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out, err
        nose.tools.assert_equal(re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out), None)

    def test_attach_files_dataset(self):
        """CLIENT(USER): Rucio attach files to dataset"""
        # Attach files to a dataset using the attach method
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # upload the files
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file2, tmp_file3)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # attach the files to the dataset
        cmd = 'rucio attach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, self.user, tmp_file2[5:], tmp_file3[5:])  # triming '/tmp/' from filenames
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # tmp_file2 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file2[5:]), out), None)
        # tmp_file3 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file3[5:]), out), None)

    def test_detach_files_dataset(self):
        """CLIENT(USER): Rucio detach files to dataset"""
        # Attach files to a dataset using the attach method
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # detach the files to the dataset
        cmd = 'rucio detach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, self.user, tmp_file2[5:], tmp_file3[5:])  # triming '/tmp/' from filenames
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        # tmp_file1 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file1[5:]), out), None)
        # tmp_file3 must be in the dataset
        nose.tools.assert_equal(re.search("{0}:{1}".format(self.user, tmp_file3[5:]), out), None)

    def test_attach_file_twice(self):
        """CLIENT(USER): Rucio attach a file twice"""
        # Attach files to a dataset using the attach method
        tmp_file1 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        # attach the files to the dataset
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dsn, self.user, tmp_file1[5:])  # triming '/tmp/' from filenames
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_not_equal(re.search("The file already exists", err), None)

    def test_detach_non_existing_file(self):
        """CLIENT(USER): Rucio detach a non existing file"""
        tmp_file1 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_dsn)
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        remove(tmp_file1)
        # attach the files to the dataset
        cmd = 'rucio detach {0} {1}:{2}'.format(tmp_dsn, self.user, 'file_ghost')  # triming '/tmp/' from filenames
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        print err
        nose.tools.assert_not_equal(re.search("Data identifier not found.", err), None)
