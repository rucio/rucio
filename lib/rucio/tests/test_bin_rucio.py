# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Cheng-Hsi Chao <cheng-hsi.chao@cern.ch>, 2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2016
# - Frank Berghaus <frank.berghaus@cern.ch>, 2017-2018
# - Tobias Wegner <twegner@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function

from os import remove, unlink, listdir, rmdir, stat, path

import json
import nose.tools
import re

from rucio.db.sqla import session, models
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.ruleclient import RuleClient
from rucio.common.config import config_get
from rucio.common.utils import generate_uuid, md5
from rucio.core.rse import add_rse_attribute
from rucio.tests.common import execute, account_name_generator, rse_name_generator, file_generator, scope_name_generator
from rucio.rse import rsemanager as rsemgr


class TestBinRucio():

    def setup(self):
        try:
            remove('/tmp/.rucio_root/auth_token_root')
        except OSError as e:
            if e.args[0] != 2:
                raise e
        self.marker = '$> '
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')
        self.user = 'data13_hip'
        self.def_rse = 'MOCK4'
        self.did_client = DIDClient()
        self.replica_client = ReplicaClient()
        self.rule_client = RuleClient()
        self.account_client = AccountLimitClient()
        self.account_client.set_account_limit('root', self.def_rse, -1)

        add_rse_attribute(self.def_rse, 'istape', 'False')

        self.upload_success_str = 'Successfully uploaded file %s'

    def test_rucio_version(self):
        """CLIENT(USER): Rucio version"""
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_true('rucio' in err)

    def test_rucio_ping(self):
        """CLIENT(USER): Rucio ping"""
        cmd = 'rucio --host %s ping' % self.host
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)

    def test_add_account(self):
        """CLIENT(ADMIN): Add account"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        nose.tools.assert_equal('Added new account: %s\n' % tmp_val, out)

    def test_whoami(self):
        """CLIENT(USER): Rucio whoami"""
        cmd = 'rucio whoami'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        nose.tools.assert_regexp_matches(out, re.compile('.*account.*'))

    def test_add_identity(self):
        """CLIENT(ADMIN): Add identity"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal('Added new account: %s\n' % tmp_val, out)
        cmd = 'rucio-admin identity add --account %s --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
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
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal('Deleted identity: jdoe@CERN.CH\n', out)
        # list identities for account
        cmd = 'rucio-admin account list-identities %s' % (tmp_acc)
        print(self.marker + cmd)
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
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
        print(out)
        print(err)
        nose.tools.assert_equal(0, exitcode)
        # list attributes
        cmd = 'rucio-admin account list-attributes {0}'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_equal(0, exitcode)
        # delete attribute to the account
        cmd = 'rucio-admin account delete-attribute {0} --key test_attribute_key'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_equal(0, exitcode)

    def test_add_scope(self):
        """CLIENT(ADMIN): Add scope"""
        tmp_scp = scope_name_generator()
        tmp_acc = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_acc
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin scope add --account %s --scope %s' % (tmp_acc, tmp_scp)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal('Added new scope to account: %s-%s\n' % (tmp_scp, tmp_acc), out)

    def test_add_rse(self):
        """CLIENT(ADMIN): Add RSE"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        nose.tools.assert_equal('Added new deterministic RSE: %s\n' % tmp_val, out)

    def test_add_rse_nondet(self):
        """CLIENT(ADMIN): Add non-deterministic RSE"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add --non-deterministic %s' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        nose.tools.assert_equal('Added new non-deterministic RSE: %s\n' % tmp_val, out)

    def test_list_rses(self):
        """CLIENT(ADMIN): List RSEs"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin rse list'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        nose.tools.assert_regexp_matches(out, re.compile('.*%s.*' % tmp_val))

    def test_upload(self):
        """CLIENT(USER): Upload"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio upload'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )

    def test_download(self):
        """CLIENT(USER): Download"""
        cmd = 'rucio download'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )

    def test_upload_file(self):
        """CLIENT(USER): Rucio upload files"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file1)) in out)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file2)) in out)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file3)) in out)

    def test_upload_file_register_after_upload(self):
        """CLIENT(USER): Rucio upload files with registration after upload"""
        # normal upload
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4} --register-after-upload'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_true((self.upload_success_str % tmp_file1_name) in out)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file2)) in out)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file3)) in out)

        # removing replica -> file on RSE should be overwritten
        # (simulating an upload error, where a part of the file is uploaded but the replica is not registered)
        db_session = session.get_session()
        db_session.query(models.RSEFileAssociation).filter_by(name=tmp_file1_name, scope=self.user).delete()
        db_session.query(models.ReplicaLock).delete()
        db_session.query(models.ReplicationRule).filter_by(name=tmp_file1_name, scope=self.user).delete()
        db_session.query(models.DataIdentifier).filter_by(name=tmp_file1_name, scope=self.user).delete()
        db_session.commit()
        tmp_file4 = file_generator()
        checksum_tmp_file4 = md5(tmp_file4)
        cmd = 'rucio -v upload --rse {0} --scope {1} --name {2} {3} --register-after-upload'.format(self.def_rse, self.user, tmp_file1_name, tmp_file4)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file4)) in out)
        nose.tools.assert_equal(checksum_tmp_file4, [replica for replica in self.replica_client.list_replicas(dids=[{'name': tmp_file1_name, 'scope': self.user}])][0]['md5'])

        # try to upload file that already exists on RSE and is already registered -> no overwrite
        cmd = 'rucio -v upload --rse {0} --scope {1} --name {2} {3} --register-after-upload'.format(self.def_rse, self.user, tmp_file1_name, tmp_file4)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file4)
        nose.tools.assert_true('File already registered' in out)

    def test_upload_file_guid(self):
        """CLIENT(USER): Rucio upload file with guid"""
        tmp_file1 = file_generator()
        tmp_guid = generate_uuid()
        cmd = 'rucio -v upload --rse {0} --guid {1} --scope {2} {3}'.format(self.def_rse, tmp_guid, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        nose.tools.assert_true((self.upload_success_str % path.basename(tmp_file1)) in out)

    def test_upload_repeated_file(self):
        """CLIENT(USER): Rucio upload repeated files"""
        # One of the files to upload is already catalogued but was removed
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        cmd = 'rucio -v upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # get the rule for the file
        cmd = "rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        rule = out
        # delete the file from the catalog
        cmd = "rucio delete-rule {0}".format(rule)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # delete the physical file
        cmd = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        nose.tools.assert_true((self.upload_success_str % tmp_file1_name) in out)

    def test_upload_repeated_file_dataset(self):
        """CLIENT(USER): Rucio upload repeated files to dataset"""
        # One of the files to upload is already in the dataset
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        tmp_file3_name = path.basename(tmp_file3)
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # upload the files to the dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # tmp_file1 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file1_name), out), None)
        # tmp_file3 must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file3_name), out), None)

    def test_upload_file_dataset(self):
        """CLIENT(USER): Rucio upload files to dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file1_name), out), None)

    def test_upload_file_dataset_register_after_upload(self):
        """CLIENT(USER): Rucio upload files to dataset with file registration after upload"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio -v upload --register-after-upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(self.def_rse, self.user, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, tmp_file1_name), out), None)

    def test_upload_adds_md5digest(self):
        """CLIENT(USER): Upload Checksums"""
        # user has a file to upload
        filename = file_generator()
        tmp_file1_name = path.basename(filename)
        file_md5 = md5(filename)
        # user uploads file
        cmd = 'rucio -v upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, filename)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # When inspecting the metadata of the new file the user finds the md5 checksum
        meta = self.did_client.get_metadata(scope=self.user, name=tmp_file1_name)
        nose.tools.assert_in('md5', meta)
        nose.tools.assert_equal(meta['md5'], file_md5)
        remove(filename)

    def test_create_dataset(self):
        """CLIENT(USER): Rucio add dataset"""
        tmp_name = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        cmd = 'rucio add-dataset ' + tmp_name
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search('Added ' + tmp_name, out), None)

    def test_add_files_to_dataset(self):
        """CLIENT(USER): Rucio add files to dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_dataset = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_file2)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # create dataset
        cmd = 'rucio add-dataset ' + tmp_dataset
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add files to dataset
        cmd = 'rucio attach {0} {3}:{1} {3}:{2}'.format(tmp_dataset, tmp_file1[5:], tmp_file2[5:], self.user)  # triming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # find the added files
        cmd = 'rucio list-files ' + tmp_dataset
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

    def test_download_file(self):
        """CLIENT(USER): Rucio download files"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:])  # triming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:-2] + '*')  # triming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except Exception:
            pass

    def test_download_filter(self):
        """CLIENT(USER): Rucio download with filter options"""
        # Use filter option to download file with wildcarded name
        tmp_file1 = file_generator()
        uuid = generate_uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --guid {2} {3}'.format(self.def_rse, self.user, uuid, tmp_file1)
        exitcode, out, err = execute(cmd)
        print(out, err)
        remove(tmp_file1)
        wrong_guid = generate_uuid()
        cmd = 'rucio -v download --dir /tmp {0}:{1} --filter guid={2}'.format(self.user, '*', wrong_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal(re.search(tmp_file1[5:], out), None)
        cmd = 'rucio -v download --dir /tmp {0}:{1} --filter guid={2}'.format(self.user, '*', uuid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

        # Only use filter option to download file
        tmp_file1 = file_generator()
        uuid = generate_uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --guid {2} {3}'.format(self.def_rse, self.user, uuid, tmp_file1)
        exitcode, out, err = execute(cmd)
        print(out, err)
        remove(tmp_file1)
        wrong_guid = generate_uuid()
        cmd = 'rucio -v download --dir /tmp --scope {0} --filter guid={1}'.format(self.user, wrong_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal(re.search(tmp_file1[5:], out), None)
        cmd = 'rucio -v download --dir /tmp --scope {0} --filter guid={1}'.format(self.user, uuid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

        # Only use filter option to download dataset
        tmp_file1 = file_generator()
        dataset_name = 'dataset_%s' % generate_uuid()
        cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(self.def_rse, self.user, tmp_file1, dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        remove(tmp_file1)
        db_session = session.get_session()
        db_session.query(models.DataIdentifier).filter_by(scope=self.user, name=dataset_name).one().length = 15
        db_session.commit()
        cmd = 'rucio download --dir /tmp --scope {0} --filter length=100'.format(self.user)
        exitcode, out, err = execute(cmd)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal(re.search(tmp_file1[5:], out), None)
        cmd = 'rucio download --dir /tmp --scope {0} --filter length=15'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_generator()
        dataset_name = 'dataset_%s' % generate_uuid()
        cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(self.def_rse, self.user, tmp_file1, dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        remove(tmp_file1)
        db_session = session.get_session()
        db_session.query(models.DataIdentifier).filter_by(scope=self.user, name=dataset_name).one().length = 1
        db_session.commit()
        cmd = 'rucio download --dir /tmp {0}:{1} --filter length=10'.format(self.user, dataset_name[0:-1] + '*')
        exitcode, out, err = execute(cmd)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal(re.search(tmp_file1[5:], out), None)
        cmd = 'rucio download --dir /tmp {0}:{1} --filter length=1'.format(self.user, dataset_name[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(tmp_file1[5:], out), None)

    def test_download_metalink_file(self):
        """CLIENT(USER): Rucio download with metalink file"""
        metalink_file_path = generate_uuid()
        scope = self.user

        # Use filter and metalink option
        cmd = 'rucio download --scope mock --filter size=1 --metalink=test'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Arguments filter and metalink cannot be used together', err)

        # Use did and metalink option
        cmd = 'rucio download --metalink=test mock:test'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Arguments dids and metalink cannot be used together', err)

        # Download only with metalink file
        tmp_file = file_generator()
        tmp_file_name = tmp_file[5:]
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, scope, tmp_file)
        exitcode, out, err = execute(cmd)
        replica_file = ReplicaClient().list_replicas([{'scope': scope, 'name': tmp_file_name}], metalink=True)
        with open(metalink_file_path, 'w+') as metalink_file:
            metalink_file.write(replica_file)
        cmd = 'rucio download --dir /tmp --metalink {0}'.format(metalink_file_path)
        exitcode, out, err = execute(cmd)
        cmd = 'ls /tmp/{0}'.format(scope)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search(tmp_file_name, out), None)

    def test_download_succeeds_md5only(self):
        """CLIENT(USER): Rucio download succeeds MD5 only"""
        # user has a file to upload
        filename = file_generator()
        file_md5 = md5(filename)
        filesize = stat(filename).st_size
        lfn = {'name': filename[5:], 'scope': self.user, 'bytes': filesize, 'md5': file_md5}
        # user uploads file
        self.replica_client.add_replicas(files=[lfn], rse=self.def_rse)
        rse_settings = rsemgr.get_rse_info(self.def_rse)
        protocol = rsemgr.create_protocol(rse_settings, 'write')
        protocol.connect()
        pfn = protocol.lfns2pfns(lfn).values()[0]
        protocol.put(filename[5:], pfn, filename[:5])
        protocol.close()
        remove(filename)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, filename[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/{0}'.format(self.user)    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(filename[5:], out), None)
        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except Exception:
            pass

    def test_download_fails_badmd5(self):
        """CLIENT(USER): Rucio download fails on MD5 mismatch"""
        # user has a file to upload
        filename = file_generator()
        file_md5 = md5(filename)
        filesize = stat(filename).st_size
        lfn = {'name': filename[5:], 'scope': self.user, 'bytes': filesize, 'md5': '0123456789abcdef0123456789abcdef'}
        # user uploads file
        self.replica_client.add_replicas(files=[lfn], rse=self.def_rse)
        rse_settings = rsemgr.get_rse_info(self.def_rse)
        protocol = rsemgr.create_protocol(rse_settings, 'write')
        protocol.connect()
        pfn = protocol.lfns2pfns(lfn).values()[0]
        protocol.put(filename[5:], pfn, filename[:5])
        protocol.close()
        remove(filename)

        # download file
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, filename[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        report = 'Local\ checksum\:\ {0},\ Rucio\ checksum\:\ 0123456789abcdef0123456789abcdef'.format(file_md5)
        print('searching', report, 'in', err)
        nose.tools.assert_not_equal(re.search(report, err), None)

        # The file should not exist
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal(re.search(filename[5:], out), None)

        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except Exception:
            pass

    def test_download_dataset(self):
        """CLIENT(USER): Rucio download dataset"""
        tmp_file1 = file_generator()
        tmp_dataset = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # create dataset
        cmd = 'rucio add-dataset ' + tmp_dataset
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add files to dataset
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dataset, self.user, tmp_file1[5:])  # triming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download dataset
        cmd = 'rucio -v download --dir /tmp {0}'.format(tmp_dataset)  # triming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        search = '{0} successfully downloaded'.format(tmp_file1[5:])  # triming '/tmp/' from filename
        nose.tools.assert_not_equal(re.search(search, err), None)

    def test_create_rule(self):
        """CLIENT(USER): Rucio add rule"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        # add quota
        self.account_client.set_account_limit('root', tmp_rse, -1)
        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add quota
        self.account_client.set_account_limit('root', tmp_rse, -1)
        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add quota
        self.account_client.set_account_limit('root', tmp_rse, -1)
        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        rule = out[:-1]  # triming new line character
        # check if rule exist for the file
        cmd = "rucio list-rules {0}:{1}".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_not_equal(re.search(rule, out), None)

    def test_delete_rule(self):
        """CLIENT(USER): rule deletion"""
        self.account_client.set_account_limit('root', self.def_rse, -1)
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        self.account_client.set_account_limit('root', tmp_rse, -1)

        # add rse atributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 1 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err)
        print(out)
        # get the rules for the file
        cmd = "rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        (rule1, rule2) = out.split()
        # delete the rules for the file
        cmd = "rucio delete-rule {0}".format(rule1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = "rucio delete-rule {0}".format(rule2)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the file
        cmd = "rucio list-dids --filter type=all {0}:{1}".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        nose.tools.assert_equal(5, len(out.splitlines()))

    def test_add_file_twice(self):
        """CLIENT(USER): Add file twice"""
        tmp_file1 = file_generator()
        # add file twice
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_equal(re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out), None)

    def test_add_delete_add_file(self):
        """CLIENT(USER): Add/Delete/Add"""
        tmp_file1 = file_generator()
        # add file
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # get the rule for the file
        cmd = "rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        rule = out
        # delete the file from the catalog
        cmd = "rucio delete-rule {0}".format(rule)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # delete the fisical file
        cmd = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # modify the file to avoid same checksum
        cmd = "echo 'delta' >> {0}".format(tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add the same file
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
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
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # upload the files
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file2, tmp_file3)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # attach the files to the dataset
        cmd = 'rucio attach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, self.user, tmp_file2[5:], tmp_file3[5:])  # triming '/tmp/' from filenames
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
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
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        # detach the files to the dataset
        cmd = 'rucio detach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, self.user, tmp_file2[5:], tmp_file3[5:])  # triming '/tmp/' from filenames
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # searching for the file in the new dataset
        cmd = 'rucio list-files {0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
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
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        # attach the files to the dataset
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dsn, self.user, tmp_file1[5:])  # triming '/tmp/' from filenames
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_not_equal(re.search("The file already exists", err), None)

    def test_attach_dataset_twice(self):
        """ CLIENT(USER): Rucio attach a dataset twice """
        container = 'container_%s' % generate_uuid()
        dataset = 'dataset_%s' % generate_uuid()
        self.did_client.add_container(scope=self.user, name=container)
        self.did_client.add_dataset(scope=self.user, name=dataset)

        # Attach dataset to container
        cmd = 'rucio attach {0}:{1} {0}:{2}'.format(self.user, container, dataset)
        exitcode, out, err = execute(cmd)

        # Attach again
        cmd = 'rucio attach {0}:{1} {0}:{2}'.format(self.user, container, dataset)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_not_equal(re.search("Data identifier already added to the destination content", err), None)

    def test_detach_non_existing_file(self):
        """CLIENT(USER): Rucio detach a non existing file"""
        tmp_file1 = file_generator()
        tmp_dsn = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(self.def_rse, self.user, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        # attach the files to the dataset
        cmd = 'rucio detach {0} {1}:{2}'.format(tmp_dsn, self.user, 'file_ghost')  # triming '/tmp/' from filenames
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        nose.tools.assert_not_equal(re.search("Data identifier not found.", err), None)

    def test_list_did_recursive(self):
        """ CLIENT(USER): List did recursive """
        # Setup nested collections
        tmp_scope = 'mock'
        tmp_container_1 = 'container_%s' % generate_uuid()
        cmd = 'rucio add-container {0}:{1}'.format(tmp_scope, tmp_container_1)
        exitcode, out, err = execute(cmd)
        tmp_container_2 = 'container_%s' % generate_uuid()
        cmd = 'rucio add-container {0}:{1}'.format(tmp_scope, tmp_container_2)
        exitcode, out, err = execute(cmd)
        tmp_container_3 = 'container_%s' % generate_uuid()
        cmd = 'rucio add-container {0}:{1}'.format(tmp_scope, tmp_container_3)
        exitcode, out, err = execute(cmd)
        cmd = 'rucio attach {0}:{1} {0}:{2}'.format(tmp_scope, tmp_container_1, tmp_container_2)
        exitcode, out, err = execute(cmd)
        cmd = 'rucio attach {0}:{1} {0}:{2}'.format(tmp_scope, tmp_container_2, tmp_container_3)
        exitcode, out, err = execute(cmd)

        # All attached DIDs are expected
        cmd = 'rucio list-dids {0}:{1} --recursive'.format(tmp_scope, tmp_container_1)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search(tmp_container_1, out), None)
        nose.tools.assert_not_equal(re.search(tmp_container_2, out), None)
        nose.tools.assert_not_equal(re.search(tmp_container_3, out), None)

        # Wildcards are not allowed to use with --recursive
        cmd = 'rucio list-dids {0}:* --recursive'.format(tmp_scope)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search("Option recursive cannot be used with wildcards", err), None)

    def test_attach_many_dids(self):
        """ CLIENT(USER): Rucio attach many (>1000) DIDs """
        # Setup data for CLI check
        tmp_dsn_name = 'Container' + rse_name_generator()
        tmp_dsn_did = self.user + ':' + tmp_dsn_name
        self.did_client.add_did(scope=self.user, name=tmp_dsn_name, type='CONTAINER')

        files = [{'name': 'dsn_%s' % generate_uuid(), 'scope': self.user, 'type': 'DATASET'} for i in range(0, 1500)]
        self.did_client.add_dids(files[:1000])
        self.did_client.add_dids(files[1000:])

        # Attaching over 1000 DIDs with CLI
        cmd = 'rucio attach {0}'.format(tmp_dsn_did)
        for tmp_file in files:
            cmd += ' {0}:{1}'.format(tmp_file['scope'], tmp_file['name'])
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)

        # Checking if the execution was successfull and if the DIDs belong together
        nose.tools.assert_not_equal(re.search('DIDs successfully attached', out), None)
        cmd = 'rucio list-content {0}'.format(tmp_dsn_did)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        # first dataset must be in the container
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, files[0]['name']), out), None)
        # last dataset must be in the container
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, files[-1]['name']), out), None)

        # Setup data with file
        did_file_path = 'list_dids.txt'
        files = [{'name': 'dsn_%s' % generate_uuid(), 'scope': self.user, 'type': 'DATASET'} for i in range(0, 1500)]
        self.did_client.add_dids(files[:1000])
        self.did_client.add_dids(files[1000:])

        with open(did_file_path, 'w') as did_file:
            for file in files:
                did_file.write(file['scope'] + ':' + file['name'] + '\n')
            did_file.close()

        # Attaching over 1000 files per file
        cmd = 'rucio attach {0} -f {1}'.format(tmp_dsn_did, did_file_path)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(did_file_path)

        # Checking if the execution was successfull and if the DIDs belong together
        nose.tools.assert_not_equal(re.search('DIDs successfully attached', out), None)
        cmd = 'rucio list-content {0}'.format(tmp_dsn_did)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        # first file must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, files[0]['name']), out), None)
        # last file must be in the dataset
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, files[-1]['name']), out), None)

    def test_attach_many_dids_twice(self):
        """ CLIENT(USER): Attach many (>1000) DIDs twice """
        # Setup data for CLI check
        container_name = 'container' + generate_uuid()
        container = self.user + ':' + container_name
        self.did_client.add_did(scope=self.user, name=container_name, type='CONTAINER')

        datasets = [{'name': 'dsn_%s' % generate_uuid(), 'scope': self.user, 'type': 'DATASET'} for i in range(0, 1500)]
        self.did_client.add_dids(datasets[:1000])
        self.did_client.add_dids(datasets[1000:])

        # Attaching over 1000 DIDs with CLI
        cmd = 'rucio attach {0}'.format(container)
        for dataset in datasets:
            cmd += ' {0}:{1}'.format(dataset['scope'], dataset['name'])
        exitcode, out, err = execute(cmd)

        # Attaching twice
        cmd = 'rucio attach {0}'.format(container)
        for dataset in datasets:
            cmd += ' {0}:{1}'.format(dataset['scope'], dataset['name'])
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search("DIDs successfully attached", out), None)

        # Attaching twice plus one DID that is not already attached
        new_dataset = {'name': 'dsn_%s' % generate_uuid(), 'scope': self.user, 'type': 'DATASET'}
        datasets.append(new_dataset)
        self.did_client.add_did(scope=self.user, name=new_dataset['name'], type='DATASET')
        cmd = 'rucio attach {0}'.format(container)
        for dataset in datasets:
            cmd += ' {0}:{1}'.format(dataset['scope'], dataset['name'])
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search("DIDs successfully attached", out), None)
        cmd = 'rucio list-content {0}'.format(container)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search("{0}:{1}".format(self.user, new_dataset['name']), out), None)

    def test_import_data(self):
        """ CLIENT(ADMIN): Import data into rucio"""
        file_path = 'data_import.json'
        data = {'rses': [{'rse': rse_name_generator()}]}
        with open(file_path, 'w+') as file:
            file.write(json.dumps(data))
        cmd = 'rucio-admin data import {0}'.format(file_path)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search('Data successfully imported', out), None)
        remove(file_path)

    def test_export_data(self):
        """ CLIENT(ADMIN): Export data from rucio"""
        file_path = 'data_export.json'
        cmd = 'rucio-admin data export {0}'.format(file_path)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search('Data successfully exported', out), None)
        remove(file_path)

    def test_set_tombstone(self):
        """ CLIENT(ADMIN): set a tombstone on a replica. """
        # Set tombstone on one replica
        rse = 'MOCK4'
        scope = 'mock'
        name = generate_uuid()
        self.replica_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
        cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search('Set tombstone successfully', err), None)

        # Set tombstone on locked replica
        name = generate_uuid()
        self.replica_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
        self.rule_client.add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
        cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search('Replica is locked', err), None)

        # Set tombstone on not found replica
        name = generate_uuid()
        cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
        exitcode, out, err = execute(cmd)
        nose.tools.assert_not_equal(re.search('Replica not found', err), None)
