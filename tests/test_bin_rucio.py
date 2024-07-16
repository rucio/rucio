# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import json
import os
import random
import re
import tempfile
from datetime import datetime, timedelta
from os import environ, listdir, path, remove, rmdir, stat, unlink

import pytest
from sqlalchemy import and_, delete

from rucio.client.accountlimitclient import AccountLimitClient
from rucio.client.configclient import ConfigClient
from rucio.client.didclient import DIDClient
from rucio.client.lifetimeclient import LifetimeClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, get_tmp_dir, md5, render_json
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import account_name_generator, execute, file_generator, get_long_vo, rse_name_generator, scope_name_generator


class TestBinRucio:

    def conf_vo(self):
        self.vo = {}
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            if 'SUITE' not in environ or environ['SUITE'] != 'client':
                # Server test, we can use short VO via DB for internal tests
                from rucio.tests.common_server import get_vo
                self.vo = {'vo': get_vo()}
            else:
                # Client-only test, only use config with no DB config
                self.vo = {'vo': get_long_vo()}
            try:
                remove(get_tmp_dir() + '/.rucio_root@%s/auth_token_for_account_root' % self.vo['vo'])
            except OSError as error:
                if error.args[0] != 2:
                    raise error

    @pytest.fixture(autouse=True)
    def setup_obj(self, vo, function_scope_prefix):
        self.conf_vo()
        try:
            remove(get_tmp_dir() + '/.rucio_root/auth_token_for_account_root')
        except OSError as e:
            if e.args[0] != 2:
                raise e
        self.marker = '$> '
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')
        self.user = 'data13_hip'
        self.rse_client = RSEClient()
        self.did_client = DIDClient()
        self.replica_client = ReplicaClient()
        self.rule_client = RuleClient()
        self.config_client = ConfigClient()
        self.lifetime_client = LifetimeClient()
        self.account_client = AccountLimitClient()
        rse_factory = None
        if environ.get('SUITE', 'remote_dbs') != 'client':
            from .temp_factories import TemporaryRSEFactory

            rse_factory = TemporaryRSEFactory(vo=vo, name_prefix=function_scope_prefix)
            self.def_rse, self.def_rse_id = rse_factory.make_posix_rse()
        else:
            self.def_rse = 'MOCK4'
            self.def_rse_id = self.rse_client.get_rse(rse=self.def_rse)['id']
        self.account_client.set_local_account_limit('root', self.def_rse, -1)

        self.rse_client.add_rse_attribute(self.def_rse, 'istape', 'False')

        self.upload_success_str = 'Successfully uploaded file %s'

        yield

        if rse_factory:
            rse_factory.cleanup()

    def test_rucio_version(self):
        """CLIENT(USER): Rucio version"""
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        assert 'rucio' in out or 'rucio' in err

    def test_rucio_ping(self):
        """CLIENT(USER): Rucio ping"""
        cmd = 'rucio --host %s ping' % self.host
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)

    def test_rucio_config_arg(self):
        """CLIENT(USER): Rucio config argument"""
        cmd = 'rucio --config errconfig ping'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 'Could not load Rucio configuration file' in err and re.match('.*errconfig.*$', err, re.DOTALL)

    def test_add_account(self):
        """CLIENT(ADMIN): Add account"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'Added new account: %s\n' % tmp_val == out

    def test_whoami(self):
        """CLIENT(USER): Rucio whoami"""
        cmd = 'rucio whoami'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'account' in out

    def test_add_identity(self):
        """CLIENT(ADMIN): Add identity"""
        tmp_val = account_name_generator()
        cmd = 'rucio-admin account add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        assert 'Added new account: %s\n' % tmp_val == out
        cmd = 'rucio-admin identity add --account %s --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'Added new identity to account: jdoe@CERN.CH-%s\n' % tmp_val == out

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
        assert 'Deleted identity: jdoe@CERN.CH\n' == out
        # list identities for account
        cmd = 'rucio-admin account list-identities %s' % (tmp_acc)
        print(self.marker + cmd)
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert '' == out

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
        assert exitcode == 0
        # list attributes
        cmd = 'rucio-admin account list-attributes {0}'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        # delete attribute to the account
        cmd = 'rucio-admin account delete-attribute {0} --key test_attribute_key'.format(tmp_acc)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

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
        assert 'Added new scope to account: %s-%s\n' % (tmp_scp, tmp_acc) == out

    def test_add_rse(self):
        """CLIENT(ADMIN): Add RSE"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'Added new deterministic RSE: %s\n' % tmp_val == out

    def test_add_rse_nondet(self):
        """CLIENT(ADMIN): Add non-deterministic RSE"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add --non-deterministic %s' % tmp_val
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'Added new non-deterministic RSE: %s\n' % tmp_val == out

    def test_list_rses(self):
        """CLIENT(ADMIN): List RSEs"""
        tmp_val = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % tmp_val
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin rse list'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert tmp_val in out

    def test_rse_add_distance(self):
        """CLIENT (ADMIN): Add distance to RSE"""
        # add RSEs
        temprse1 = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % temprse1
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        temprse2 = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % temprse2
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

        # add distance between the RSEs
        cmd = 'rucio-admin rse add-distance --distance 1 --ranking 1 %s %s' % (temprse1, temprse2)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        cmd = 'rucio-admin rse add-distance --distance 1 --ranking 1 %s %s' % (temprse2, temprse1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

        # add duplicate distance
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err, exitcode)
        assert exitcode != 0
        assert 'Distance from %s to %s already exists!' % (temprse2, temprse1) in err

    def test_rse_delete_distance(self):
        """CLIENT (ADMIN): Delete distance to RSE"""
        # add RSEs
        temprse1 = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % temprse1
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        temprse2 = rse_name_generator()
        cmd = 'rucio-admin rse add %s' % temprse2
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

        # add distance between the RSEs
        cmd = 'rucio-admin rse add-distance --distance 1 --ranking 1 %s %s' % (temprse1, temprse2)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

        # delete distance OK
        cmd = 'rucio-admin rse delete-distance %s %s' % (temprse1, temprse2)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        assert "Deleted distance information from %s to %s." % (temprse1, temprse2) in out

        # delete distance RSE not found
        cmd = 'rucio-admin rse delete-distance %s %s' % (temprse1, generate_uuid())
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 'RSE does not exist.' in err

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
        upload_string_1 = (self.upload_success_str % path.basename(tmp_file1))
        upload_string_2 = (self.upload_success_str % path.basename(tmp_file2))
        upload_string_3 = (self.upload_success_str % path.basename(tmp_file3))
        assert upload_string_1 in out or upload_string_1 in err
        assert upload_string_2 in out or upload_string_2 in err
        assert upload_string_3 in out or upload_string_3 in err

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
        upload_string_1 = (self.upload_success_str % path.basename(tmp_file1))
        upload_string_2 = (self.upload_success_str % path.basename(tmp_file2))
        upload_string_3 = (self.upload_success_str % path.basename(tmp_file3))
        assert upload_string_1 in out or upload_string_1 in err
        assert upload_string_2 in out or upload_string_2 in err
        assert upload_string_3 in out or upload_string_3 in err

        # removing replica -> file on RSE should be overwritten
        # (simulating an upload error, where a part of the file is uploaded but the replica is not registered)
        if 'SUITE' not in environ or environ['SUITE'] != 'client':
            from rucio.db.sqla import models, session
            db_session = session.get_session()
            internal_scope = InternalScope(self.user, **self.vo)
            for model in [models.RSEFileAssociation, models.ReplicaLock, models.ReplicationRule, models.DidMeta, models.DataIdentifier]:
                stmt = delete(
                    model
                ).where(
                    and_(model.name == tmp_file1_name,
                         model.scope == internal_scope)
                )
                db_session.execute(stmt)
            db_session.commit()
            tmp_file4 = file_generator()
            checksum_tmp_file4 = md5(tmp_file4)
            cmd = 'rucio -v upload --rse {0} --scope {1} --name {2} {3} --register-after-upload'.format(self.def_rse, self.user, tmp_file1_name, tmp_file4)
            print(self.marker + cmd)
            exitcode, out, err = execute(cmd)
            print(out)
            print(err)
            assert (self.upload_success_str % path.basename(tmp_file4)) in out or (self.upload_success_str % path.basename(tmp_file4)) in err
            assert checksum_tmp_file4 == [replica for replica in self.replica_client.list_replicas(dids=[{'name': tmp_file1_name, 'scope': self.user}])][0]['md5']

            # try to upload file that already exists on RSE and is already registered -> no overwrite
            cmd = 'rucio -v upload --rse {0} --scope {1} --name {2} {3} --register-after-upload'.format(self.def_rse, self.user, tmp_file1_name, tmp_file4)
            print(self.marker + cmd)
            exitcode, out, err = execute(cmd)
            print(out)
            print(err)
            remove(tmp_file4)
            assert 'File already registered' in out or 'File already registered' in err

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
        upload_string_1 = (self.upload_success_str % path.basename(tmp_file1))
        assert upload_string_1 in out or upload_string_1 in err

    def test_upload_file_with_impl(self):
        """CLIENT(USER): Rucio upload file with impl parameter assigned 'posix' value"""
        tmp_file1 = file_generator()
        impl = 'posix'
        cmd = 'rucio -v upload --rse {0} --scope {1} --impl {2} {3}'.format(self.def_rse, self.user, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        upload_string_1 = (self.upload_success_str % path.basename(tmp_file1))
        assert re.search(upload_string_1, err) is not None

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
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1_name)
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
        upload_string_1 = (self.upload_success_str % tmp_file1_name)
        assert upload_string_1 in out or upload_string_1 in err

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
        assert re.search("{0}:{1}".format(self.user, tmp_file1_name), out) is not None
        # tmp_file3 must be in the dataset
        assert re.search("{0}:{1}".format(self.user, tmp_file3_name), out) is not None

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
        assert re.search("{0}:{1}".format(self.user, tmp_file1_name), out) is not None

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
        assert re.search("{0}:{1}".format(self.user, tmp_file1_name), out) is not None

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
        assert 'md5' in meta
        assert meta['md5'] == file_md5
        remove(filename)

    def test_upload_expiration_date(self):
        """CLIENT(USER): Rucio upload files"""
        tmp_file = file_generator()
        cmd = 'rucio -v upload --rse {0} --scope {1} --expiration-date 2021-10-10-20:00:00 --lifetime 20000  {2}'.format(self.def_rse, self.user, tmp_file)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode != 0
        assert "--lifetime and --expiration-date cannot be specified at the same time." in err

        cmd = 'rucio -v upload --rse {0} --scope {1} --expiration-date 2021----10-10-20:00:00 {2}'.format(self.def_rse, self.user, tmp_file)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode != 0
        assert "does not match format '%Y-%m-%d-%H:%M:%S'" in err

        cmd = 'rucio -v upload --rse {0} --scope {1} --expiration-date 2021-10-10-20:00:00 {2}'.format(self.def_rse, self.user, tmp_file)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode != 0
        assert "The specified expiration date should be in the future!" in err

        cmd = 'rucio -v upload --rse {0} --scope {1} --expiration-date 2030-10-10-20:00:00 {2}'.format(self.def_rse, self.user, tmp_file)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        remove(tmp_file)
        upload_string = (self.upload_success_str % path.basename(tmp_file))
        assert upload_string in out or upload_string in err

    def test_create_dataset(self):
        """CLIENT(USER): Rucio add dataset"""
        tmp_name = self.user + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
        cmd = 'rucio add-dataset ' + tmp_name
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search('Added ' + tmp_name, out) is not None

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
        cmd = 'rucio attach {0} {3}:{1} {3}:{2}'.format(tmp_dataset, tmp_file1[5:], tmp_file2[5:], self.user)  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # find the added files
        cmd = 'rucio list-files ' + tmp_dataset
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

    def test_download_file(self):
        """CLIENT(USER): Rucio download files"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:-2] + '*')  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except Exception:
            pass

    def test_download_pfn(self):
        """CLIENT(USER): Rucio download files"""
        tmp_file1 = file_generator()
        name = os.path.basename(tmp_file1)
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)

        # download files
        download_dir = "/temp"
        replica_pfn = list(self.replica_client.list_replicas([{'scope': self.user, 'name': name}]))[0]['rses'][self.def_rse][0]
        cmd = f'rucio -v download  --dir {download_dir} --rse {self.def_rse} --pfn {replica_pfn} {self.user}:{name}'
        exitcode, out, err = execute(cmd)
        if "Access to local destination denied." in err:  # Known issue - see #6506
            assert False, f"test `test_download_pfn` unable to access file {self.user}/{name} in {download_dir}"
        else:
            assert re.search('Total files.*1', out) is not None

        # Try to use the --pfn without rse
        cmd = f"rucio -v download  --dir {download_dir.rstrip('/')}/duplicate --pfn {replica_pfn} {self.user}:{name}"
        exitcode, out, err = execute(cmd)

        assert "No RSE was given, selecting one." in err
        assert exitcode == 0
        assert re.search('Total files.*1', out) is not None

        # Download the pfn without an rse, except there is no RSE with that RSE
        non_existent_pfn = "http://fake.pfn.marker/"
        cmd = f"rucio -v download  --dir {download_dir.rstrip('/')}/duplicate --pfn {non_existent_pfn} {self.user}:{name}"
        exitcode, out, err = execute(cmd)

        assert "No RSE was given, selecting one." in err
        assert f"Could not find RSE for pfn {non_existent_pfn}" in err
        assert exitcode != 0

        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except Exception:
            pass

    def test_download_file_with_impl(self):
        """CLIENT(USER): Rucio download files with impl parameter assigned 'posix' value"""
        tmp_file1 = file_generator()
        impl = 'posix'
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(self.def_rse, self.user, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2}'.format(self.user, tmp_file1[5:], impl)  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(self.def_rse, self.user, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2}'.format(self.user, tmp_file1[5:-2] + '*', impl)  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

        try:
            for i in listdir('data13_hip'):
                unlink('data13_hip/%s' % i)
            rmdir('data13_hip')
        except Exception:
            pass

    @pytest.mark.noparallel(reason='fails when run in parallel')
    def test_download_no_subdir(self):
        """CLIENT(USER): Rucio download files with --no-subdir and check that files already found locally are not replaced"""
        tmp_file = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        # download files with --no-subdir
        cmd = 'rucio -v download --no-subdir --dir /tmp {0}:{1}'.format(self.user, tmp_file[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert tmp_file[5:] in out
        # download again with --no-subdir
        cmd = 'rucio -v download --no-subdir --dir /tmp {0}:{1}'.format(self.user, tmp_file[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        assert re.search(r'Downloaded files:\s+0', out) is not None
        assert re.search(r'Files already found locally:\s+1', out) is not None

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
        assert re.search(tmp_file1[5:], out) is None
        cmd = 'rucio -v download --dir /tmp {0}:{1} --filter guid={2}'.format(self.user, '*', uuid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

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
        assert re.search(tmp_file1[5:], out) is None
        cmd = 'rucio -v download --dir /tmp --scope {0} --filter guid={1}'.format(self.user, uuid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

        # Only use filter option to download dataset
        tmp_file1 = file_generator()
        dataset_name = 'dataset_%s' % generate_uuid()
        cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(self.def_rse, self.user, tmp_file1, dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        remove(tmp_file1)
        cmd = 'rucio download --dir /tmp --scope {0} --filter created_before=1900-01-01T00:00:00.000Z'.format(self.user)
        exitcode, out, err = execute(cmd)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is None
        cmd = 'rucio download --dir /tmp --scope {0} --filter created_after=1900-01-01T00:00:00.000Z'.format(self.user)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # TODO: https://github.com/rucio/rucio/issues/2926 !
        # assert re.search(tmp_file1[5:], out) is not None

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_generator()
        cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(self.def_rse, self.user, tmp_file1, dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        remove(tmp_file1)
        cmd = 'rucio download --dir /tmp {0}:{1} --filter created_before=1900-01-01T00:00:00.000Z'.format(self.user, dataset_name[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is None
        cmd = 'rucio download --dir /tmp {0}:{1} --filter created_after=1900-01-01T00:00:00.000Z'.format(self.user, dataset_name[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(dataset_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1[5:], out) is not None

    def test_download_timeout_options_accepted(self):
        """CLIENT(USER): Rucio download timeout options """
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio download --dir /tmp --transfer-timeout 3 --transfer-speed-timeout 1000 {0}:{1}'.format(self.user, tmp_file1[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 'successfully downloaded' in err
        # search for the files with ls
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        # Check that PFN the transfer-speed-timeout option is not accepted for --pfn
        cmd = 'rucio -v download --rse {0} --transfer-speed-timeout 1 --pfn http://a.b.c/ {1}:{2}'.format(self.def_rse, self.user, tmp_file1)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert "Download with --pfn doesn't support --transfer-speed-timeout" in err

    def test_download_metalink_file(self):
        """CLIENT(USER): Rucio download with metalink file"""
        metalink_file_path = generate_uuid()
        scope = self.user

        # Use filter and metalink option
        cmd = 'rucio download --scope mock --filter size=1 --metalink=test'
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 'Arguments filter and metalink cannot be used together' in err

        # Use did and metalink option
        cmd = 'rucio download --metalink=test mock:test'
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 'Arguments dids and metalink cannot be used together' in err

        # Download only with metalink file
        tmp_file = file_generator()
        tmp_file_name = tmp_file[5:]
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, scope, tmp_file)
        exitcode, out, err = execute(cmd)
        print(out, err)
        replica_file = ReplicaClient().list_replicas([{'scope': scope, 'name': tmp_file_name}], metalink=True)
        with open(metalink_file_path, 'w+') as metalink_file:
            metalink_file.write(replica_file)
        cmd = 'rucio download --dir /tmp --metalink {0}'.format(metalink_file_path)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert '{} successfully downloaded'.format(tmp_file_name) in err
        assert re.search('Total files.*1', out) is not None
        remove(metalink_file_path)
        cmd = 'ls /tmp/{0}'.format(scope)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file_name, out) is not None

    def test_download_succeeds_md5only(self):
        """CLIENT(USER): Rucio download succeeds MD5 only"""
        # user has a file to upload
        filename = file_generator()
        file_md5 = md5(filename)
        filesize = stat(filename).st_size
        lfn = {'name': filename[5:], 'scope': self.user, 'bytes': filesize, 'md5': file_md5}
        # user uploads file
        self.replica_client.add_replicas(files=[lfn], rse=self.def_rse)
        rse_settings = rsemgr.get_rse_info(rse=self.def_rse, **self.vo)
        protocol = rsemgr.create_protocol(rse_settings, 'write')
        protocol.connect()
        pfn = list(protocol.lfns2pfns(lfn).values())[0]
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
        assert re.search(filename[5:], out) is not None
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
        rse_settings = rsemgr.get_rse_info(rse=self.def_rse, **self.vo)
        protocol = rsemgr.create_protocol(rse_settings, 'write')
        protocol.connect()
        pfn = list(protocol.lfns2pfns(lfn).values())[0]
        protocol.put(filename[5:], pfn, filename[:5])
        protocol.close()
        remove(filename)

        # download file
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, filename[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        report = r'Local\ checksum\:\ {0},\ Rucio\ checksum\:\ 0123456789abcdef0123456789abcdef'.format(file_md5)
        print('searching', report, 'in', err)
        assert re.search(report, err) is not None

        # The file should not exist
        cmd = 'ls /tmp/'    # search in /tmp/
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(filename[5:], out) is None

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
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dataset, self.user, tmp_file1[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        os.remove(tmp_file1)

        # download dataset
        cmd = 'rucio -v download --dir /tmp {0}'.format(tmp_dataset)  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        search = '{0} successfully downloaded'.format(tmp_file1[5:])  # trimming '/tmp/' from filename
        assert re.search(search, err) is not None

    def test_download_file_check_by_size(self):
        """CLIENT(USER): Rucio download files"""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # download files
        cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # Alter downloaded file
        cmd = 'echo "dummy" >> /tmp/{}/{}'.format(self.user, tmp_file1[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        # Download file again and check for mismatch
        cmd = 'rucio -v download --check-local-with-filesize-only --dir /tmp {0}:{1}'.format(self.user, tmp_file1[5:])  # trimming '/tmp/' from filename
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        assert "File with same name exists locally, but filesize mismatches" in err

    def test_list_blocklisted_replicas(self):
        """CLIENT(USER): Rucio list replicas"""
        # add rse
        tmp_rse = rse_name_generator()
        cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'rucio-admin rse add-protocol --hostname blocklistreplica --scheme file --prefix /rucio --port 0 --impl rucio.rse.protocols.posix.Default ' \
              '--domain-json \'{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}}\' %s' % tmp_rse
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        # add files
        tmp_file1 = file_generator()
        file_name = tmp_file1[5:]  # trimming '/tmp/' from filename
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(tmp_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        # create dataset
        tmp_dataset = self.user + ':DSet' + rse_name_generator()
        cmd = 'rucio add-dataset ' + tmp_dataset
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add files to dataset
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dataset, self.user, file_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        # Listing the replica should work before blocklisting the RSE
        cmd = 'rucio list-file-replicas {}'.format(tmp_dataset)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert tmp_rse in out

        # Blocklist the rse
        cmd = 'rucio-admin rse update --rse {} --setting availability_read --value False'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert not err

        # list-file-replicas should, by default, list replicas from blocklisted rses
        cmd = 'rucio list-file-replicas {}'.format(tmp_dataset)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert tmp_rse in out

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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert not err
        rule = out[:-1]  # trimming new line character
        assert re.match(r'^\w+$', rule)
        # check if rule exist for the file
        cmd = "rucio list-rules {0}:{1}".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(rule, out) is not None

    def test_create_rule_delayed(self):
        """CLIENT(USER): Rucio add rule delayed"""
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
        print(out, err)
        # add quota
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASRULEDELAYED'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # try adding rule with an incorrect delay-injection. Must fail
        cmd = "rucio add-rule --delay-injection asdsaf {0}:{1} 1 'spacetoken=ATLASRULEDELAYED'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        assert err
        # Add a correct rule
        cmd = "rucio add-rule --delay-injection 3600 {0}:{1} 1 'spacetoken=ATLASRULEDELAYED'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert not err
        rule = out[:-1]  # trimming new line character
        cmd = "rucio rule-info {0}".format(rule)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        out_lines = out.splitlines()
        assert any(re.match(r'State:.* INJECT', line) for line in out_lines)
        assert any(re.match(r'Locks OK/REPLICATING/STUCK:.* 0/0/0', line) for line in out_lines)
        # Check that "Created at" is approximately 3600 seconds in the future
        [created_at_line] = filter(lambda x: "Created at" in x, out_lines)
        created_at = re.search(r'Created at:\s+(\d.*\d)$', created_at_line).group(1)
        created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
        assert datetime.utcnow() + timedelta(seconds=3550) < created_at < datetime.utcnow() + timedelta(seconds=3650)

    def test_delete_rule(self):
        """CLIENT(USER): rule deletion"""
        self.account_client.set_local_account_limit('root', self.def_rse, -1)
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)

        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASDELETERULE'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 1 'spacetoken=ATLASDELETERULE'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err)
        print(out)
        # get the rules for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
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
        cmd = "rucio list-dids --filter type==all {0}:{1}".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 5 == len(out.splitlines())

    def test_move_rule(self):
        """CLIENT(USER): Rucio move rule"""
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert not err
        rule = out[:-1]  # trimming new line character
        assert re.match(r'^\w+$', rule)

        # move rule
        new_rule_expr = "'spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD'"
        cmd = "rucio move-rule {} {}".format(rule, new_rule_expr)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert not err
        new_rule = out[:-1]  # trimming new line character

        # check if rule exist for the file
        cmd = "rucio list-rules {0}:{1}".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(new_rule, out) is not None

    def test_move_rule_with_arguments(self):
        """CLIENT(USER): Rucio move rule"""
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)
        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert not err
        rule = out[:-1]  # trimming new line character
        assert re.match(r'^\w+$', rule)
        # move rule
        new_rule_expr = "spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD"
        new_rule_activity = "No User Subscription"
        new_rule_source_replica_expression = "spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD"
        cmd = "rucio move-rule --activity '{}' --source-replica-expression '{}' {} '{}'".format(new_rule_activity, new_rule_source_replica_expression, rule, new_rule_expr)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert not err
        new_rule_id = out[:-1]  # trimming new line character

        # check if rule exist for the file
        cmd = "rucio list-rules {0}:{1}".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(new_rule_id, out) is not None
        # check updated rule information
        cmd = "rucio rule-info {0}".format(new_rule_id)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert new_rule_activity in out
        assert new_rule_source_replica_expression in out

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
        assert re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out) is None

    def test_add_delete_add_file(self):
        """CLIENT(USER): Add/Delete/Add"""
        tmp_file1 = file_generator()
        # add file
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # get the rule for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
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
        assert re.search("File {0}:{1} successfully uploaded on the storage".format(self.user, tmp_file1[5:]), out) is None

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
        cmd = 'rucio attach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, self.user, tmp_file2[5:], tmp_file3[5:])  # trimming '/tmp/' from filenames
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
        assert re.search("{0}:{1}".format(self.user, tmp_file2[5:]), out) is not None
        # tmp_file3 must be in the dataset
        assert re.search("{0}:{1}".format(self.user, tmp_file3[5:]), out) is not None

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
        cmd = 'rucio detach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, self.user, tmp_file2[5:], tmp_file3[5:])  # trimming '/tmp/' from filenames
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
        assert re.search("{0}:{1}".format(self.user, tmp_file1[5:]), out) is not None
        # tmp_file3 must be in the dataset
        assert re.search("{0}:{1}".format(self.user, tmp_file3[5:]), out) is None

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
        cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dsn, self.user, tmp_file1[5:])  # trimming '/tmp/' from filenames
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert re.search("The file already exists", err) is not None

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
        assert re.search("Data identifier already added to the destination content", err) is not None

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
        cmd = 'rucio detach {0} {1}:{2}'.format(tmp_dsn, self.user, 'file_ghost')  # trimming '/tmp/' from filenames
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert re.search("Data identifier not found.", err) is not None

    @pytest.mark.dirty
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
        assert re.search(tmp_container_1, out) is not None
        assert re.search(tmp_container_2, out) is not None
        assert re.search(tmp_container_3, out) is not None

        # Wildcards are not allowed to use with --recursive
        cmd = 'rucio list-dids {0}:* --recursive'.format(tmp_scope)
        exitcode, out, err = execute(cmd)
        assert re.search("Option recursive cannot be used with wildcards", err) is not None

    @pytest.mark.dirty
    def test_attach_many_dids(self):
        """ CLIENT(USER): Rucio attach many (>1000) DIDs """
        # Setup data for CLI check
        tmp_dsn_name = 'Container' + rse_name_generator()
        tmp_dsn_did = self.user + ':' + tmp_dsn_name
        self.did_client.add_did(scope=self.user, name=tmp_dsn_name, did_type='CONTAINER')

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

        # Checking if the execution was successful and if the DIDs belong together
        assert re.search('DIDs successfully attached', out) is not None
        cmd = 'rucio list-content {0}'.format(tmp_dsn_did)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        # first dataset must be in the container
        assert re.search("{0}:{1}".format(self.user, files[0]['name']), out) is not None
        # last dataset must be in the container
        assert re.search("{0}:{1}".format(self.user, files[-1]['name']), out) is not None

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

        # Checking if the execution was successful and if the DIDs belong together
        assert re.search('DIDs successfully attached', out) is not None
        cmd = 'rucio list-content {0}'.format(tmp_dsn_did)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        # first file must be in the dataset
        assert re.search("{0}:{1}".format(self.user, files[0]['name']), out) is not None
        # last file must be in the dataset
        assert re.search("{0}:{1}".format(self.user, files[-1]['name']), out) is not None

    @pytest.mark.dirty
    def test_attach_many_dids_twice(self):
        """ CLIENT(USER): Attach many (>1000) DIDs twice """
        # Setup data for CLI check
        container_name = 'container' + generate_uuid()
        container = self.user + ':' + container_name
        self.did_client.add_did(scope=self.user, name=container_name, did_type='CONTAINER')

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
        assert re.search("DIDs successfully attached", out) is not None

        # Attaching twice plus one DID that is not already attached
        new_dataset = {'name': 'dsn_%s' % generate_uuid(), 'scope': self.user, 'type': 'DATASET'}
        datasets.append(new_dataset)
        self.did_client.add_did(scope=self.user, name=new_dataset['name'], did_type='DATASET')
        cmd = 'rucio attach {0}'.format(container)
        for dataset in datasets:
            cmd += ' {0}:{1}'.format(dataset['scope'], dataset['name'])
        exitcode, out, err = execute(cmd)
        assert re.search("DIDs successfully attached", out) is not None
        cmd = 'rucio list-content {0}'.format(container)
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, new_dataset['name']), out) is not None

    @pytest.mark.noparallel(reason='might override global RSE settings')
    def test_import_data(self):
        """ CLIENT(ADMIN): Import data into rucio"""
        file_path = 'data_import.json'
        rses = {rse['rse']: rse for rse in self.rse_client.list_rses()}
        rses[rse_name_generator()] = {'country_name': 'test'}
        data = {'rses': rses}
        with open(file_path, 'w+') as file:
            file.write(render_json(**data))
        cmd = 'rucio-admin data import {0}'.format(file_path)
        exitcode, out, err = execute(cmd)
        assert re.search('Data successfully imported', out) is not None
        remove(file_path)

    @pytest.mark.noparallel(reason='fails when run in parallel')
    def test_export_data(self):
        """ CLIENT(ADMIN): Export data from rucio"""
        file_path = 'data_export.json'
        cmd = 'rucio-admin data export {0}'.format(file_path)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search('Data successfully exported', out) is not None
        remove(file_path)

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='fails when run in parallel')
    def test_set_tombstone(self):
        """ CLIENT(ADMIN): set a tombstone on a replica. """
        # Set tombstone on one replica
        rse = self.def_rse
        scope = 'mock'
        name = generate_uuid()
        self.replica_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
        cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
        exitcode, out, err = execute(cmd)
        assert re.search('Set tombstone successfully', err) is not None

        # Set tombstone on locked replica
        name = generate_uuid()
        self.replica_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
        self.rule_client.add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
        cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
        exitcode, out, err = execute(cmd)
        assert re.search('Replica is locked', err) is not None

        # Set tombstone on not found replica
        name = generate_uuid()
        cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
        exitcode, out, err = execute(cmd)
        assert re.search('Replica not found', err) is not None

    @pytest.mark.noparallel(reason='modifies account limit on pre-defined RSE')
    def test_list_account_limits(self):
        """ CLIENT (USER): list account limits. """
        rse = self.def_rse
        rse_exp = f'MOCK3|{rse}'
        account = 'root'
        local_limit = 10
        global_limit = 20
        self.account_client.set_local_account_limit(account, rse, local_limit)
        self.account_client.set_global_account_limit(account, rse_exp, global_limit)
        cmd = 'rucio list-account-limits {0}'.format(account)
        exitcode, out, err = execute(cmd)
        assert re.search('.*{0}.*{1}.*'.format(rse, local_limit), out) is not None
        assert re.search('.*{0}.*{1}.*'.format(rse_exp, global_limit), out) is not None
        cmd = 'rucio list-account-limits --rse {0} {1}'.format(rse, account)
        exitcode, out, err = execute(cmd)
        assert re.search('.*{0}.*{1}.*'.format(rse, local_limit), out) is not None
        assert re.search('.*{0}.*{1}.*'.format(rse_exp, global_limit), out) is not None
        self.account_client.set_local_account_limit(account, rse, -1)
        self.account_client.set_global_account_limit(account, rse_exp, -1)

    @pytest.mark.noparallel(reason='modifies account limit on pre-defined RSE')
    @pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'client', reason='uses abacus daemon and core functions')
    def test_list_account_usage(self):
        """ CLIENT (USER): list account usage. """
        from rucio.core.account_counter import increase
        from rucio.daemons.abacus import account as abacus_account
        from rucio.db.sqla import models, session

        db_session = session.get_session()
        for model in [models.AccountUsage, models.AccountLimit, models.AccountGlobalLimit, models.UpdatedAccountCounter]:
            stmt = delete(model)
            db_session.execute(stmt)
        db_session.commit()
        rse = self.def_rse
        rse_id = self.def_rse_id
        rse_exp = f'MOCK|{rse}'
        account = 'root'
        usage = 4
        local_limit = 10
        local_left = local_limit - usage
        global_limit = 20
        global_left = global_limit - usage
        self.account_client.set_local_account_limit(account, rse, local_limit)
        self.account_client.set_global_account_limit(account, rse_exp, global_limit)
        increase(rse_id, InternalAccount(account, **self.vo), 1, usage)
        abacus_account.run(once=True)
        cmd = 'rucio list-account-usage {0}'.format(account)
        exitcode, out, err = execute(cmd)
        assert re.search('.*{0}.*{1}.*{2}.*{3}'.format(rse, usage, local_limit, local_left), out) is not None
        assert re.search('.*{0}.*{1}.*{2}.*{3}'.format(f'MOCK|{rse}', usage, global_limit, global_left), out) is not None

        cmd = 'rucio list-account-usage --rse {0} {1}'.format(rse, account)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert re.search('.*{0}.*{1}.*{2}.*{3}'.format(rse, usage, local_limit, local_left), out) is not None
        assert re.search('.*{0}.*{1}.*{2}.*{3}'.format(f'MOCK|{rse}', usage, global_limit, global_left), out) is not None
        self.account_client.set_local_account_limit(account, rse, -1)
        self.account_client.set_global_account_limit(account, rse_exp, -1)

    def test_get_set_delete_limits_rse(self):
        """CLIENT(ADMIN): Get, set and delete RSE limits"""
        name = generate_uuid()
        value = random.randint(0, 100000)
        name2 = generate_uuid()
        value2 = random.randint(0, 100000)
        name3 = generate_uuid()
        value3 = account_name_generator()
        cmd = 'rucio-admin rse set-limit %s %s %s' % (self.def_rse, name, value)
        execute(cmd)
        cmd = 'rucio-admin rse set-limit %s %s %s' % (self.def_rse, name2, value2)
        execute(cmd)
        cmd = 'rucio-admin rse info %s' % self.def_rse
        exitcode, out, err = execute(cmd)
        assert re.search("{0}: {1}".format(name, value), out) is not None
        assert re.search("{0}: {1}".format(name2, value2), out) is not None
        new_value = random.randint(100001, 999999999)
        cmd = 'rucio-admin rse set-limit %s %s %s' % (self.def_rse, name, new_value)
        execute(cmd)
        cmd = 'rucio-admin rse info %s' % self.def_rse
        exitcode, out, err = execute(cmd)
        assert re.search("{0}: {1}".format(name, new_value), out) is not None
        assert re.search("{0}: {1}".format(name, value), out) is None
        assert re.search("{0}: {1}".format(name2, value2), out) is not None
        cmd = 'rucio-admin rse delete-limit %s %s' % (self.def_rse, name)
        execute(cmd)
        cmd = 'rucio-admin rse info %s' % self.def_rse
        exitcode, out, err = execute(cmd)
        assert re.search("{0}: {1}".format(name, new_value), out) is None
        assert re.search("{0}: {1}".format(name2, value2), out) is not None
        cmd = 'rucio-admin rse delete-limit %s %s' % (self.def_rse, name)
        exitcode, out, err = execute(cmd)
        assert re.search('Limit {0} not defined in RSE {1}'.format(name, self.def_rse), err) is not None
        cmd = 'rucio-admin rse set-limit %s %s %s' % (self.def_rse, name3, value3)
        exitcode, out, err = execute(cmd)
        assert re.search('The RSE limit value must be an integer', err) is not None
        cmd = 'rucio-admin rse info %s' % self.def_rse
        exitcode, out, err = execute(cmd)
        assert re.search("{0}: {1}".format(name3, value3), out) is None
        assert re.search("{0}: {1}".format(name2, value2), out) is not None

    def test_upload_recursive_ok(self):
        """CLIENT(USER): Upload and preserve folder structure"""
        folder = 'folder_' + generate_uuid()
        folder1 = '%s/folder_%s' % (folder, generate_uuid())
        folder2 = '%s/folder_%s' % (folder, generate_uuid())
        folder3 = '%s/folder_%s' % (folder, generate_uuid())
        folder11 = '%s/folder_%s' % (folder1, generate_uuid())
        folder12 = '%s/folder_%s' % (folder1, generate_uuid())
        folder13 = '%s/folder_%s' % (folder1, generate_uuid())
        file1 = 'file_%s' % generate_uuid()
        file2 = 'file_%s' % generate_uuid()
        cmd = 'mkdir %s' % folder
        execute(cmd)
        cmd = 'mkdir %s && mkdir %s && mkdir %s' % (folder1, folder2, folder3)
        execute(cmd)
        cmd = 'mkdir %s && mkdir %s && mkdir %s' % (folder11, folder12, folder13)
        execute(cmd)
        cmd = 'echo "%s" > %s/%s.txt' % (generate_uuid(), folder11, file1)
        execute(cmd)
        cmd = 'echo "%s" > %s/%s.txt' % (generate_uuid(), folder2, file2)
        execute(cmd)
        cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (self.user, self.def_rse, folder)
        execute(cmd)
        cmd = 'rucio list-content %s:%s' % (self.user, folder)
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, folder1.split('/')[-1]), out) is not None
        assert re.search("{0}:{1}".format(self.user, folder2.split('/')[-1]), out) is not None
        assert re.search("{0}:{1}".format(self.user, folder3.split('/')[-1]), out) is None
        cmd = 'rucio list-content %s:%s' % (self.user, folder1.split('/')[-1])
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, folder11.split('/')[-1]), out) is not None
        assert re.search("{0}:{1}".format(self.user, folder12.split('/')[-1]), out) is None
        assert re.search("{0}:{1}".format(self.user, folder13.split('/')[-1]), out) is None
        cmd = 'rucio list-content %s:%s' % (self.user, folder11.split('/')[-1])
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, file1), out) is not None
        cmd = 'rucio list-content %s:%s' % (self.user, folder2.split('/')[-1])
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, file2), out) is not None
        cmd = 'rm -rf %s' % folder
        execute(cmd)

    def test_upload_recursive_subfolder(self):
        """CLIENT(USER): Upload and preserve folder structure in a subfolder"""
        folder = 'folder_' + generate_uuid()
        folder1 = '%s/folder_%s' % (folder, generate_uuid())
        folder11 = '%s/folder_%s' % (folder1, generate_uuid())
        file1 = 'file_%s' % generate_uuid()
        cmd = 'mkdir %s' % (folder)
        execute(cmd)
        cmd = 'mkdir %s' % (folder1)
        execute(cmd)
        cmd = 'mkdir %s' % (folder11)
        execute(cmd)
        cmd = 'echo "%s" > %s/%s.txt' % (generate_uuid(), folder11, file1)
        execute(cmd)
        cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (self.user, self.def_rse, folder1)
        execute(cmd)
        cmd = 'rucio list-content %s:%s' % (self.user, folder)
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, folder1.split('/')[-1]), out) is None
        cmd = 'rucio list-content %s:%s' % (self.user, folder1.split('/')[-1])
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, folder11.split('/')[-1]), out) is not None
        cmd = 'rucio list-content %s:%s' % (self.user, folder11.split('/')[-1])
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, file1), out) is not None
        cmd = 'rm -rf %s' % folder
        execute(cmd)

    def test_recursive_empty(self):
        """CLIENT(USER): Upload and preserve folder structure with an empty folder"""
        folder = 'folder_' + generate_uuid()
        folder1 = '%s/folder_%s' % (folder, generate_uuid())
        cmd = 'mkdir %s' % (folder)
        execute(cmd)
        cmd = 'mkdir %s' % (folder1)
        execute(cmd)
        cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (self.user, self.def_rse, folder)
        execute(cmd)
        cmd = 'rucio list-content %s:%s' % (self.user, folder)
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, folder1.split('/')[-1]), out) is None
        cmd = 'rm -rf %s' % folder
        execute(cmd)

    def test_upload_recursive_only_files(self):
        """CLIENT(USER): Upload and preserve folder structure only with files"""
        folder = 'folder_' + generate_uuid()
        file1 = 'file_%s' % generate_uuid()
        file2 = 'file_%s' % generate_uuid()
        file3 = 'file_%s' % generate_uuid()
        cmd = 'mkdir %s' % folder
        execute(cmd)
        cmd = 'echo "%s" > %s/%s.txt' % (generate_uuid(), folder, file1)
        execute(cmd)
        cmd = 'echo "%s" > %s/%s.txt' % (generate_uuid(), folder, file2)
        execute(cmd)
        cmd = 'echo "%s" > %s/%s.txt' % (generate_uuid(), folder, file3)
        execute(cmd)
        cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (self.user, self.def_rse, folder)
        execute(cmd)
        cmd = 'rucio list-content %s:%s' % (self.user, folder)
        exitcode, out, err = execute(cmd)
        assert re.search("{0}:{1}".format(self.user, file1), out) is not None
        assert re.search("{0}:{1}".format(self.user, file2), out) is not None
        assert re.search("{0}:{1}".format(self.user, file3), out) is not None
        cmd = 'rucio ls %s:%s' % (self.user, folder)
        exitcode, out, err = execute(cmd)
        assert re.search("DATASET", out) is not None
        cmd = 'rm -rf %s' % folder
        execute(cmd)

    def test_deprecated_command_line_args(self):
        """CLIENT(USER): Warn about deprecated command line args"""
        cmd = 'rucio get --trace_appid 0'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        assert 'Warning: The commandline argument --trace_appid is deprecated! Please use --trace-appid in the future.' in out

    def test_rucio_admin_expiration_date_is_deprecated(self):
        """CLIENT(USER): Warn about deprecated command line args"""
        cmd = 'rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --expiration-date 168 --reason \'test only\''
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert 'Warning: The commandline argument --expiration-date is deprecated! Please use --duration in the future.' in out

    def test_rucio_admin_expiration_date_not_defined(self):
        """CLIENT(USER): Warn about deprecated command line arg"""
        cmd = 'rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --reason \'test only\''
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert err != 0
        assert 'the following arguments are required' in err

    def test_rucio_admin_duration_out_of_bounds(self):
        """CLIENT(USER): Warn about deprecated command line arg"""
        cmd = 'rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --duration 622080000 --reason \'test only\''
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert err != 0
        assert re.search(r'The given duration of 7199 days exceeds the maximum duration of 30 days.', err)

    def test_update_rule_cancel_requests_args(self):
        """CLIENT(USER): update rule cancel requests must have a state defined"""
        cmd = 'rucio update-rule --cancel-requests RULE'
        exitcode, out, err = execute(cmd)
        assert '--stuck or --suspend must be specified when running --cancel-requests' in err
        assert exitcode != 0

    def test_update_rule_unset_child_rule(self):
        """CLIENT(USER): update rule unsets a child rule property"""

        # PREPARING FILE AND RSE
        # add files
        tmp_file = file_generator()
        tmp_fname = tmp_file[5:]
        cmd = f'rucio upload --rse {self.def_rse} --scope {self.user} {tmp_file}'
        exitcode, out, err = execute(cmd)
        assert 'ERROR' not in err

        for i in range(2):
            tmp_rse = rse_name_generator()
            cmd = f'rucio-admin rse add {tmp_rse}'
            exitcode, out, err = execute(cmd)
            assert not err

            self.account_client.set_local_account_limit('root', tmp_rse, -1)

            cmd = (f'rucio-admin rse set-attribute --rse {tmp_rse}'
                   f' --key spacetoken --value RULELOC{i}')
            exitcode, out, err = execute(cmd)
            assert not err

        # PREPARING THE RULES
        # add rule
        rule_expr = "spacetoken=RULELOC0"
        cmd = f"rucio add-rule {self.user}:{tmp_fname} 1 '{rule_expr}'"
        exitcode, out, err = execute(cmd)
        assert not err
        # get the rules for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".\
            format(self.user, tmp_file[5:])
        exitcode, out, err = execute(cmd)
        parentrule_id, _ = out.split()

        # LINKING THE RULES (PARENT/CHILD)
        # move rule
        new_rule_expr = rule_expr + "|spacetoken=RULELOC1"
        cmd = f"rucio move-rule {parentrule_id} '{new_rule_expr}'"
        exitcode, out, err = execute(cmd)
        childrule_id = out.strip()
        assert err == ''

        # check if new rule exists for the file
        cmd = "rucio list-rules {0}:{1}".format(self.user, tmp_fname)
        exitcode, out, err = execute(cmd)
        assert re.search(childrule_id, out) is not None

        # DETACHING THE RULES
        # child-rule-id None means to unset the variable on the parent rule
        cmd = f"rucio update-rule --child-rule-id None {parentrule_id}"
        exitcode, out, err = execute(cmd)
        assert 'ERROR' not in err
        assert re.search('Updated Rule', out) is not None

        cmd = f"rucio update-rule --child-rule-id None {parentrule_id}"
        exitcode, out, err = execute(cmd)
        print(err)
        assert 'ERROR' in err
        assert re.search('Cannot detach child when no such relationship exists', err) is not None

    def test_update_rule_no_child_selfassign(self):
        """CLIENT(USER): do not permit to assign self as own child"""
        tmp_file = file_generator()
        tmp_fname = tmp_file[5:]
        cmd = f'rucio upload --rse {self.def_rse} --scope {self.user} {tmp_file}'
        exitcode, out, err = execute(cmd)
        assert 'ERROR' not in err

        tmp_rse = rse_name_generator()
        cmd = f'rucio-admin rse add {tmp_rse}'
        exitcode, out, err = execute(cmd)
        assert not err

        self.account_client.set_local_account_limit('root', tmp_rse, -1)

        cmd = (f'rucio-admin rse set-attribute --rse {tmp_rse}'
               f' --key spacetoken --value RULELOC')
        exitcode, out, err = execute(cmd)
        assert not err

        # PREPARING THE RULES
        # add rule
        rule_expr = "spacetoken=RULELOC"
        cmd = f"rucio add-rule {self.user}:{tmp_fname} 1 '{rule_expr}'"
        exitcode, out, err = execute(cmd)
        assert not err

        # get the rules for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".\
            format(self.user, tmp_file[5:])
        exitcode, out, err = execute(cmd)
        parentrule_id, _ = out.split()

        # now for the test
        # TODO: merge this with the other update_rule test from issue #5930
        cmd = f"rucio update-rule --child-rule-id {parentrule_id} {parentrule_id}"
        exitcode, out, err = execute(cmd)
        # TODO: add a more specific assertion here.
        assert err

    def test_update_rule_boost_rule_arg(self):
        """CLIENT(USER): update a rule with the `--boost_rule` option """
        self.account_client.set_local_account_limit('root', self.def_rse, -1)
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)

        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASDELETERULE'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 1 'spacetoken=ATLASDELETERULE'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err)
        print(out)
        # get the rules for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        (rule1, rule2) = out.split()

        # update the rules
        cmd = "rucio update-rule --boost-rule {0}".format(rule1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        print(out, err)
        cmd = "rucio update-rule --boost-rule {0}".format(rule2)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0

    def test_rucio_list_file_replicas(self):
        """CLIENT(USER): List missing file replicas """
        self.account_client.set_local_account_limit('root', self.def_rse, -1)
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
        self.account_client.set_local_account_limit('root', tmp_rse, -1)

        # add rse attributes
        cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value MARIOSPACEODYSSEY'.format(tmp_rse)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # add rules
        cmd = "rucio add-rule {0}:{1} 1 'spacetoken=MARIOSPACEODYSSEY'".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err)
        print(out)

        cmd = 'rucio list-file-replicas {0}:{1} --rses "spacetoken=MARIOSPACEODYSSEY" --missing'.format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        assert tmp_file1[5:] in out

    def test_rucio_create_rule_with_0_copies(self):
        """CLIENT(USER): The creation of a rule with 0 copies shouldn't be possible."""
        tmp_file1 = file_generator()
        # add files
        cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(self.def_rse, self.user, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)

        # Try to add a rules with 0 copies, this shouldn't be possible
        cmd = "rucio add-rule {0}:{1} 0 MOCK".format(self.user, tmp_file1[5:])
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err)
        print(out)
        assert exitcode != 0
        assert "The number of copies for a replication rule should be greater than 0." in err

    def test_add_lifetime_exception(self):
        """ CLIENT(USER): Rucio submission of lifetime exception """
        container = 'container_%s' % generate_uuid()
        dataset = 'dataset_%s' % generate_uuid()
        self.did_client.add_container(scope=self.user, name=container)
        self.did_client.add_dataset(scope=self.user, name=dataset)
        filename = get_tmp_dir() + 'lifetime_exception.txt'
        with open(filename, 'w') as file_:
            file_.write('%s:%s\n' % (self.user, dataset))

        # Try adding an exception
        cmd = 'rucio add-lifetime-exception --inputfile %s --reason "%s" --expiration %s' % (filename, 'Needed for analysis', '2015-10-30')
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(exitcode, out, err)
        assert exitcode == 0
        assert "Nothing to submit" in err

        with open(filename, 'w') as file_:
            file_.write('%s:%s\n' % (self.user, dataset))
            file_.write('%s:%s' % (self.user, container))

        # Try adding an exception
        cmd = 'rucio add-lifetime-exception --inputfile %s --reason "%s" --expiration %s' % (filename, 'Needed for analysis', '2015-10-30')
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(exitcode, out, err)
        assert exitcode == 0
        assert "One or more DIDs are containers. They will be resolved into a list of datasets" in err

        try:
            remove(filename)
        except OSError as err:
            if err.args[0] != 2:
                raise err

    def test_add_lifetime_exception_large_dids_number(self):
        """ CLIENT(USER): Check that exceptions with more than 1k DIDs are supported """
        filename = get_tmp_dir() + 'lifetime_exception_many_dids.txt'
        with open(filename, 'w') as file_:
            for _ in range(2000):
                file_.write('%s:%s\n' % (self.user, generate_uuid()))

        # Try adding an exception
        cmd = 'rucio add-lifetime-exception --inputfile %s --reason "%s" --expiration %s' % (filename, 'Needed for analysis', '2015-10-30')
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(exitcode, out, err)
        assert exitcode == 0
        assert "Nothing to submit" in err

        try:
            remove(filename)
        except OSError as err:
            if err.args[0] != 2:
                raise err

    def test_admin_rse_update_unsupported_option(self):
        """ ADMIN CLIENT: Rse update should throw an unsupported option exception on an unsupported exception."""
        exitcode, out, err = execute("rucio-admin rse update --setting test_with_non_existing_option --value 3 --rse {}".format(self.def_rse))
        print(out, err)
        assert exitcode != 0
        assert "Details: The key 'test_with_non_existing_option' does not exist for RSE properties." in err

        exitcode, out, err = execute("rucio-admin rse update --setting country_name --value France --rse {}".format(self.def_rse))
        print(out, err)
        assert exitcode == 0
        assert not err

    @pytest.mark.noparallel(reason='Modify config')
    def test_lifetime_cli(self):
        """ CLIENT(USER): Check CLI to declare lifetime exceptions """
        # Setup data for CLI check
        tmp_dsn_name = 'container' + rse_name_generator()
        tmp_dsn_did = self.user + ':' + tmp_dsn_name
        self.did_client.add_did(scope=self.user, name=tmp_dsn_name, did_type='DATASET')
        self.did_client.set_metadata(scope=self.user, name=tmp_dsn_name, key='eol_at', value=(datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d'))
        self.config_client.set_config_option(section='lifetime_model', option='cutoff_date', value=(datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d'))
        with tempfile.NamedTemporaryFile(mode="w+") as fp:
            fp.write(f'{tmp_dsn_did}\n' * 2)
            fp.seek(0)
            exitcode, out, err = execute("rucio add-lifetime-exception --inputfile %s --reason 'For testing purpose; please ignore.' --expiration 2124-01-01" % fp.name)
            assert 'does not exist' not in err

    def test_lifetime_container_resolution(self):
        """ CLIENT(USER): Check that the CLI to declare lifetime exceptions resolve contaiers"""
        # Setup data for CLI check
        tmp_dsn_name1 = 'dataset' + rse_name_generator()
        tmp_dsn_name2 = 'dataset' + rse_name_generator()
        tmp_cnt_name = 'container' + rse_name_generator()
        tmp_cnt_did = self.user + ':' + tmp_cnt_name
        # Create 2 datasets and 1 container and attach dataset to container
        self.did_client.add_did(scope=self.user, name=tmp_dsn_name1, did_type='DATASET')
        self.did_client.add_did(scope=self.user, name=tmp_dsn_name2, did_type='DATASET')
        self.did_client.add_did(scope=self.user, name=tmp_cnt_name, did_type='CONTAINER')
        self.did_client.attach_dids(scope=self.user, name=tmp_cnt_name, dids=[{'scope': self.user, 'name': tmp_dsn_name1}, {'scope': self.user, 'name': tmp_dsn_name2}])
        # Set eol_at for the first dataset but not to the second one
        self.did_client.set_metadata(scope=self.user, name=tmp_dsn_name1, key='eol_at', value=(datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d'))
        self.config_client.set_config_option(section='lifetime_model', option='cutoff_date', value=(datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d'))
        with tempfile.NamedTemporaryFile(mode="w+") as fp:
            fp.write(f'{tmp_cnt_did}')
            fp.seek(0)
            exitcode, out, err = execute("rucio add-lifetime-exception --inputfile %s --reason 'For testing purpose; please ignore.' --expiration 2124-01-01" % fp.name)
            print(exitcode, out, err)
            assert '%s:%s is not affected by the lifetime model' % (self.user, tmp_dsn_name2)
            assert '%s:%s will be declared' % (self.user, tmp_dsn_name1)
        list_exceptions = [(excep['scope'], excep['name']) for excep in self.lifetime_client.list_exceptions()]
        assert (self.user, tmp_dsn_name1) in list_exceptions
        assert (self.user, tmp_dsn_name2) not in list_exceptions


class TestBinTranslations:
    """
    Test that each command refresh command works the same as the old ones
    """

    def test_account(self):
        tmp_val = account_name_generator()
        old_command = f'rucio-admin account add {tmp_val}'
        _, out, _ = execute(old_command)
        new_account = account_name_generator()
        new_command = f"rucio add account --account-name {new_account}"
        exitcode, refreshed_out, _ = execute(new_command)
        assert exitcode == 0
        assert out.replace(tmp_val, new_account) == refreshed_out

        new_command = f"rucio set account --account-name {new_account} --key email --value jdoe@cern.ch"
        exitcode, _, err = execute(new_command)
        assert exitcode == 0
        assert 'ERROR' not in err

        new_command = "rucio --view history list account --account-name root"
        exitcode, _, err = execute(new_command)
        assert exitcode == 0
        assert "ERROR" not in err

    def test_account_attribute(self, jdoe_account):
        fake_key = generate_uuid()[:15]
        cmd = f'rucio-admin account add-attribute {jdoe_account} --key test_{fake_key}_key --value true'
        _, out, old_log = execute(cmd)
        new_fake_key = generate_uuid()[:15]
        cmd = f'rucio add account attribute --account-name {jdoe_account} --attr-key test_{new_fake_key}_key --attr-value true'
        exitcode, new_out, log = execute(cmd)
        assert exitcode == 0
        assert old_log.replace(fake_key, new_fake_key) == log

        cmd = f'rucio-admin account list-attributes {jdoe_account}'
        _, out, _ = execute(cmd)
        cmd = f'rucio list account attribute --account-name {jdoe_account}'
        exitcode, new_out, _ = execute(cmd)
        assert exitcode == 0
        assert out == new_out

        cmd = f'rucio-admin account delete-attribute {jdoe_account} --key test_{fake_key}_key'
        _, out, _ = execute(cmd)
        cmd = f'rucio remove account attribute --account-name {jdoe_account} --attr-key test_{new_fake_key}_key'
        exitcode, new_out, _ = execute(cmd)
        assert exitcode == 0
        assert out.replace(fake_key, new_fake_key) == new_out

    def test_account_ban(self):
        tmp_account = account_name_generator()
        execute(f'rucio-admin account add {tmp_account}')

        cmd = f'rucio-admin account ban --account {tmp_account}'
        _, _, ban_log = execute(cmd)
        cmd = f'rucio-admin account unban --account {tmp_account}'
        _, _, unban_log = execute(cmd)

        cmd = f"rucio set account ban --account-name {tmp_account}"
        exitcode, _, new_ban_log = execute(cmd)
        assert exitcode == 0
        assert ban_log == new_ban_log

        cmd = f"rucio unset account ban --account-name {tmp_account}"
        exitcode, _, new_unban_log = execute(cmd)
        assert exitcode == 0
        assert unban_log == new_unban_log

    def test_account_identities(self, jdoe_account):
        cmd = "rucio-admin account identity list-identities"
        _, out, _ = execute(cmd)
        cmd = "rucio list account identities"
        _, new_out, _ = execute(cmd)
        assert out == new_out

        cmd = f"rucio-admin account identity list-identities {jdoe_account}"
        _, out, _ = execute(cmd)
        cmd = f"rucio list account identities --acount_name {jdoe_account}"
        _, new_out, _ = execute(cmd)
        assert out == new_out

    def test_account_limits(self, jdoe_account, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        cmd = f"rucio-admin account get_limits {jdoe_account} {mock_rse}"
        _, out, _ = execute(cmd)
        cmd = f"rucio list account limits --acount-name {jdoe_account} --rse {mock_rse}"
        _, new_out, _ = execute(cmd)
        assert out == new_out

        bytes_limit = 10
        cmd = f"rucio-admin account set-limits {jdoe_account} {mock_rse} {bytes_limit}"
        _, _, set_log = execute(cmd)
        cmd = f"rucio-admin account delete-limits {jdoe_account} {mock_rse}"
        _, _, delete_log = execute(cmd)

        cmd = f"rucio add account limits --account-name {jdoe_account} --rse {mock_rse} --bytes {bytes_limit}"
        _, _, new_set_log = execute(cmd)
        assert new_set_log == set_log

        cmd = f"rucio remove account limits --account-name {jdoe_account} --rse {mock_rse}"
        _, _, new_rm_log = execute(cmd)
        assert new_rm_log == delete_log

    @pytest.mark.noparallel("Changes config settings")
    def test_config(self):
        cmd = "rucio-admin config get"
        _, out, _ = execute(cmd)
        cmd = 'rucio list config'
        exitcode, new_out, _ = execute(cmd)
        assert exitcode == 0
        assert out == new_out

        _, out, _ = execute('rucio-admin config get --section vo-map')
        exitcode, new_out, _ = execute('rucio list config --section vo-map')
        assert exitcode == 0
        assert out == new_out

        section = "vo-map"
        option = 'new_option'
        value = 'new_value'

        _, set_out, _ = execute(f"rucio-admin config set --section {section} --option {option} --value {value}")
        _, delete_out, _ = execute(f"rucio-admin config delete --section {section} --option {option}")

        cmd = f"rucio set config --section {section} --option {option} --value {value}"
        exitcode, new_set_out, _ = execute(cmd)
        assert exitcode == 0
        assert set_out.replace("rucio-admin", "rucio") == new_set_out

        cmd = f"rucio unset config --section {section} --option {option}"
        exitcode, unset_out, _ = execute(cmd)
        assert exitcode == 0
        assert unset_out == delete_out.replace("rucio-admin", "rucio")

    def test_did(self, mock_scope):
        cmd = f'rucio list did --did {mock_scope}:*'
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        file = file_generator().split('/')[-1]
        cmd = f"rucio -v add did --type dataset --did {mock_scope}:{file}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        cmd = f'rucio list did --did {mock_scope}:*'
        exitcode, new_out, err = execute(cmd)
        assert exitcode == 0
        assert f"{mock_scope}:{file}" in new_out
        assert "ERROR" not in err

        file = file_generator().split('/')[-1]
        cmd = f"rucio add did --type container --did {mock_scope}:{file}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        cmd = f'rucio list did --did {mock_scope}:*'
        exitcode, new_out, err = execute(cmd)
        assert exitcode == 0
        assert f"{mock_scope}:{file}" in new_out
        assert "ERROR" not in err

    def test_did_history(self):
        cmd = "rucio list did history"
        exitcode, _, err = execute(cmd)

        assert exitcode == 0
        assert "ERROR" not in err

    def test_attach_did(self, did_factory, rse_factory):
        did = did_factory.random_file_did()
        scope, name = did['scope'], did['name']
        cmd = f"rucio list did attachment --did {scope}:{name} --child"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert out != ''

        cmd = f"rucio list did attachment --did {scope}:{name} --parent"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert out != ''
        assert 'ERROR' not in err

        mock_rse, _ = rse_factory.make_posix_rse()
        dids = did_factory.upload_test_dataset(mock_rse)

        scope = dids[0]['dataset_scope']
        dataset = dids[0]['dataset_name']
        test_did = dids[0]['did_name']

        cmd = f"rucio remove did attachment --target {scope}:{dataset} --did {scope}:{test_did}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        cmd = f"rucio add did attachment --target {scope}:{dataset} --did {scope}:{test_did}"
        exitcode, _, err = execute(cmd)
        print(err)
        assert exitcode == 0
        assert "ERROR" not in err

    def test_lifetime_exception(self, rse_factory, did_factory):
        input_file = "./tmp/tmp_exception_files.txt"
        mock_rse, _ = rse_factory.make_posix_rse()
        did = did_factory.upload_test_dataset(mock_rse)

        with open(input_file, 'w') as f:
            f.write(f"{did[0]['dataset_scope']}:{did[0]['dataset_name']}")

        cmd = f"rucio add lifetime-exception --input-file {input_file} --reason mock_test --expiration 2100-12-30"
        exitcode, _, err = execute(cmd)
        print(err)
        assert exitcode == 0
        if "not affected by the lifetime model" not in err:
            assert "ERROR" not in err
        else:
            assert "Nothing to submit" in err

    def test_replica(self, did_factory, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        did = did_factory.upload_test_file(mock_rse)
        scope, name = did['scope'], did['name']
        cmd = f"rucio list replica --replica-type dataset --dids {scope}:{name}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        cmd = f"rucio list replica --replica-type file --dids {scope}:{name}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

    def test_replica_pfn(self, rucio_client, did_factory, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        did = did_factory.upload_test_file(mock_rse)
        scope, name = did['scope'], did['name']
        rucio_client.add_replica(mock_rse, scope, name, 1, 'deadbeef')  # I don't know why this is the default adler32

        cmd = f"rucio list replica pfn --did {scope}:{name} --rse {mock_rse}"
        exitcode, out, err = execute(cmd)

        assert exitcode == 0
        assert out is not None
        assert 'ERROR' not in err

    def test_replica_state(self, rse_factory, mock_scope, rucio_client):
        mock_rse, _ = rse_factory.make_posix_rse()

        name = generate_uuid()
        rucio_client.add_replica(mock_rse, mock_scope.external, name, 4, 'aaaaaaaa')
        cmd = f"rucio set replica state --bad --did {mock_scope.external}:{name} --rse {mock_rse}"
        exitcode, _, log = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in log

        name = generate_uuid()
        rucio_client.add_replica(mock_rse, mock_scope.external, name, 4, 'aaaaaaaa')
        cmd = f"rucio set replica state --temporary-unavailable --did {mock_scope.external}:{name} --rse {mock_rse} --duration 12"
        exitcode, _, log = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in log

        name = generate_uuid()
        rucio_client.add_replica(mock_rse, mock_scope.external, name, 4, 'aaaaaaaa')
        cmd = f"rucio set replica state --quarantine --did {mock_scope.external}:{name} --rse {mock_rse}"
        exitcode, _, log = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in log

    def test_replica_tombstone(self, rucio_client, did_factory, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        rule_rse, _ = rse_factory.make_posix_rse()
        did = did_factory.upload_test_file(mock_rse)
        scope, name = did['scope'], did['name']

        name = generate_uuid()
        rucio_client.add_replica(rule_rse, scope, name, 4, 'aaaaaaaa')

        cmd = f"rucio add replica tombstone --dids {scope}:{name} --rse {rule_rse}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

    def test_rse(self):
        rse_name = rse_name_generator()
        cmd = f"rucio add rse --rse {rse_name}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        rse_expression = rse_name.split('_')[0]
        cmd = f"rucio list rse --rse {rse_expression}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err
        assert rse_name in out

        # cmd = f"rucio -v --view info list rse --rse {rse_expression}"
        # exitcode, _, err = execute(cmd)
        # print(err)
        # assert exitcode == 0
        # assert "ERROR" not in err

        cmd = f"rucio set rse --rse {rse_name} --key name --value {rse_name_generator()}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        cmd = f"rucio remove rse --rse {rse_name}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

    def test_rse_attribute(self):
        rse_name = rse_name_generator()
        _, _, err = execute(f"rucio add rse --rse {rse_name}")
        assert "ERROR" not in err

        cmd = f"rucio list rse attribute --rse {rse_name}"
        _, _, err = execute(cmd)
        assert 'ERROR' not in err

        cmd = f"rucio set rse attribute --rse {rse_name} --key name --value {rse_name}"
        _, _, err = execute(cmd)
        assert 'ERROR' not in err

    def test_rse_protocol(self):
        rse_name = rse_name_generator()
        _, _, err = execute(f"rucio add rse --rse {rse_name}")
        assert "ERROR" not in err

        domain_json = '''{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}}'''
        cmd = f"rucio -v add rse protocol --rse {rse_name} --host-name blocklistreplica --scheme file --prefix /rucio --port 0 --impl rucio.rse.protocols.posix.Default --domain-json '{domain_json}'"
        exitcode, _, err = execute(cmd)
        assert "ERROR" not in err
        assert exitcode == 0

        cmd = f'rucio remove rse protocol --rse {rse_name} --host-name blocklistreplica --scheme file'
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

    def test_rse_distance(self, rse_factory):
        source_rse, _ = rse_factory.make_posix_rse()
        dest_rse, _ = rse_factory.make_posix_rse()

        cmd = f"rucio add rse distance --rse {source_rse} --destination {dest_rse} --distance 1"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        cmd = f"rucio list rse distance --rse {source_rse} --destination {dest_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        assert dest_rse in out
        assert '1' in out

        cmd = f"rucio set rse distance --rse {source_rse} --destination {dest_rse} --distance 10"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        cmd = f"rucio list rse distance --rse {source_rse} --destination {dest_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        assert dest_rse in out
        assert '10' in out

        cmd = f"rucio remove rse distance --rse {source_rse} --destination {dest_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

    def test_rse_limits(self, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        limit = 'mock_limit'
        cmd = f"rucio add rse limit --rse {mock_rse} --name {limit} --limit 100"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        cmd = f"rucio remove rse limit --rse {mock_rse} --name {limit}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

    def test_rse_qos_policy(self, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        policy = 'SOMETHING_I_GUESS'
        cmd = f"rucio add rse qos-policy --rse {mock_rse} --qos-policy {policy}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err
        assert policy in out

        cmd = f"rucio list rse qos-policy --rse {mock_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err
        assert policy in out

        cmd = f"rucio remove rse qos-policy --rse {mock_rse} --qos-policy {policy}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err
        assert policy in out

        cmd = f"rucio list rse qos-policy --rse {mock_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err
        assert policy not in out

    def test_rse_usage(self, rse_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        cmd = f"rucio list rse usage --rse {mock_rse}"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        cmd = f"rucio list rse usage --rse {mock_rse} --show-accounts"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

    def test_rule(self, rse_factory, did_factory):
        mock_rse, _ = rse_factory.make_posix_rse()
        rule_rse, _ = rse_factory.make_posix_rse()

        did = did_factory.upload_test_file(mock_rse)
        scope, name = did['scope'], did['name']

        cmd = f"rucio add rule --did {scope}:{name} --copies 1 --rse {rule_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err
        rule_id = out.strip('\n')

        cmd = f"rucio list rule --did {scope}:{name}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err
        assert rule_id in out

        move_rse, _ = rse_factory.make_posix_rse()
        cmd = f"rucio set rule --rule-id {rule_id} --move --rse {move_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        cmd = f"rucio set rule --rule-id {rule_id} --priority 3"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

        # Do one without a child rule so i can delete it
        additional_rse, _ = rse_factory.make_posix_rse()
        cmd = f"rucio add rule --did {scope}:{name} --copies 1 --rse {additional_rse}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err
        rule_id = out.strip('\n')

        cmd = f"rucio remove rule --rule-id {rule_id}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'ERROR' not in err

    def test_scope(self):
        new_scope = scope_name_generator()
        cmd = f"rucio add scope --scope {new_scope} --account root"
        exitcode, _, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err

        cmd = "rucio list scope"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "ERROR" not in err
        assert new_scope in out

    def test_subscription(self):
        subscription_name = generate_uuid()

        filter_ = json.dumps({})
        rules = json.dumps([{"copies": 1, "rse_expression": "JDOE_DATADISK", "lifetime": 3600, "activity": "User Subscriptions"}])

        cmd = f"rucio -v add subscription --account root --name {subscription_name} --filter '{filter_}' --rules '{rules}'"
        exitcode, _, err = execute(cmd)
        print(err)
        assert exitcode == 0
        assert "ERROR" not in err
