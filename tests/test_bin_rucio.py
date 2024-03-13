# -*- coding: utf-8 -*-
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

import os
import random
import re
import tempfile
from datetime import datetime, timedelta
from os import remove, stat, path, environ
import pytest

from rucio.common.utils import generate_uuid, get_tmp_dir, md5, render_json
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import execute


def test_rucio_version():
    """CLIENT(USER): Rucio version"""
    cmd = 'bin/rucio --version'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert 'rucio' in out or 'rucio' in err


def test_rucio_ping(rucio_client):
    host = rucio_client.host
    """CLIENT(USER): Rucio ping"""
    cmd = f'rucio --host {host} ping'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0


def test_rucio_config_arg():
    """CLIENT(USER): Rucio config argument"""
    cmd = 'rucio --config errconfig ping'
    exitcode, out, err = execute(cmd)
    assert 'Could not load Rucio configuration file' in err and re.match('.*errconfig.*$', err, re.DOTALL)


def test_add_account(account_name_generator):
    """CLIENT(ADMIN): Add account"""
    tmp_val = account_name_generator()
    cmd = 'rucio-admin account add %s' % tmp_val
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert 'Added new account: %s\n' % tmp_val == out


def test_whoami():
    """CLIENT(USER): Rucio whoami"""
    cmd = 'rucio whoami'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert 'account' in out


def test_add_identity(account_name_generator):
    """CLIENT(ADMIN): Add identity"""
    temp_account = account_name_generator()
    cmd = f'rucio-admin account add {temp_account}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f'Added new account: {temp_account}\n' == out
    cmd = f'rucio-admin identity add --account {temp_account} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f'Added new identity to account: jdoe@CERN.CH-{temp_account}\n' == out


def test_del_identity(account_name_generator):
    """CLIENT(ADMIN): Test del identity"""
    temp_account = account_name_generator()

    # create account
    cmd = f'rucio-admin account add {temp_account}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add identity to account
    cmd = f'rucio-admin identity add --account {temp_account} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # delete identity from account
    cmd = f'rucio-admin identity delete --account {temp_account} --type GSS --id jdoe@CERN.CH'
    exitcode, out, err = execute(cmd)
    assert 'Deleted identity: jdoe@CERN.CH\n' == out
    assert exitcode == 0

    # list identities for account
    cmd = f'rucio-admin account list-identities {temp_account}'
    exitcode, out, err = execute(cmd)
    assert '' == out
    assert exitcode == 0


def test_attributes(account_name_generator):
    """CLIENT(ADMIN): Add/List/Delete attributes"""
    temp_account = account_name_generator()

    # create account
    cmd = f'rucio-admin account add {temp_account}'
    exitcode, out, err = execute(cmd)
    # add attribute to the account
    cmd = f'rucio-admin account add-attribute {temp_account} --key test_attribute_key --value true'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # list attributes
    cmd = f'rucio-admin account list-attributes {temp_account}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # delete attribute to the account
    cmd = f'rucio-admin account delete-attribute {temp_account} --key test_attribute_key'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0


def test_add_scope(account_name_generator, scope_name_generator):
    """CLIENT(ADMIN): Add scope"""
    temp_scope = scope_name_generator()
    temp_account = account_name_generator()
    cmd = f'rucio-admin account add {temp_account}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    cmd = f'rucio-admin scope add --account {temp_account} --scope {temp_scope}'
    exitcode, out, err = execute(cmd)
    assert f'Added new scope to account: {temp_scope}-{temp_account}\n' == out
    assert exitcode == 0


def test_add_rse(rse_name_generator):
    """CLIENT(ADMIN): Add RSE"""
    temp_rse = rse_name_generator()
    cmd = f'rucio-admin rse add {temp_rse}'
    exitcode, out, err = execute(cmd)
    assert f'Added new deterministic RSE: {temp_rse}\n' == out
    assert exitcode == 0


def test_add_rse_nondet(rse_name_generator):
    """CLIENT(ADMIN): Add non-deterministic RSE"""
    temp_rse = rse_name_generator()
    cmd = f'rucio-admin rse add --non-deterministic {temp_rse}'
    exitcode, out, err = execute(cmd)
    assert f'Added new non-deterministic RSE: {temp_rse}\n' == out
    assert exitcode == 0


def test_list_rses(rse_name_generator):
    """CLIENT(ADMIN): List RSEs"""
    temp_rse = rse_name_generator()
    cmd = f'rucio-admin rse add {temp_rse}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    cmd = 'rucio-admin rse list'
    exitcode, out, err = execute(cmd)
    assert temp_rse in out
    assert exitcode == 0


def test_rse_add_distance(rse_name_generator):
    """CLIENT (ADMIN): Add distance to RSE"""
    # add RSEs
    temprse1 = rse_name_generator()
    cmd = 'rucio-admin rse add %s' % temprse1
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    temprse2 = rse_name_generator()
    cmd = 'rucio-admin rse add %s' % temprse2
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add distance between the RSEs
    cmd = 'rucio-admin rse add-distance --distance 1 --ranking 1 %s %s' % (temprse1, temprse2)
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0

    # add duplicate distance
    exitcode, out, err = execute(cmd)
    print(err)
    assert exitcode != 0
    assert f'Details: Distance from {temprse1} to {temprse2} already exists!\n' in err


def test_rse_delete_distance(rse_name_generator):
    """CLIENT (ADMIN): Delete distance to RSE"""
    # add RSEs
    temp_rse1 = rse_name_generator()
    temp_rse2 = rse_name_generator()

    cmd = f'rucio-admin rse add {temp_rse1}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    cmd = f'rucio-admin rse add {temp_rse2}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add distance between the RSEs
    cmd = f'rucio-admin rse add-distance --distance 1 --ranking 1 {temp_rse1} {temp_rse2}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # delete distance OK
    cmd = f'rucio-admin rse delete-distance {temp_rse1} {temp_rse2}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Deleted distance information from {temp_rse1} to {temp_rse2}." in out

    # delete distance RSE not found
    non_added_rse = rse_name_generator()
    cmd = f'rucio-admin rse delete-distance {temp_rse1} {non_added_rse}'
    exitcode, out, err = execute(cmd)
    assert 'RSE does not exist.' in err
    assert exitcode != 0


def test_upload_file(file_factory, client_rse_factory, mock_scope, upload_success_str):
    """CLIENT(USER): Rucio upload files"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope} {tmp_file1} {tmp_file2} {tmp_file3}'
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0

    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    upload_string_1 = upload_success_str(path.basename(tmp_file1))
    upload_string_2 = upload_success_str(path.basename(tmp_file2))
    upload_string_3 = upload_success_str(path.basename(tmp_file3))
    assert upload_string_1 in out or upload_string_1 in err
    assert upload_string_2 in out or upload_string_2 in err
    assert upload_string_3 in out or upload_string_3 in err


def test_upload_file_register_after_upload(file_factory, client_rse_factory, mock_scope, upload_success_str, rucio_client):
    """CLIENT(USER): Rucio upload files with registration after upload"""
    # normal upload
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope} {tmp_file1} {tmp_file2} {tmp_file3}'
    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    assert exitcode == 0

    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    upload_string_1 = upload_success_str(path.basename(tmp_file1))
    upload_string_2 = upload_success_str(path.basename(tmp_file2))
    upload_string_3 = upload_success_str(path.basename(tmp_file3))
    assert upload_string_1 in out or upload_string_1 in err
    assert upload_string_2 in out or upload_string_2 in err
    assert upload_string_3 in out or upload_string_3 in err

    # removing replica -> file on RSE should be overwritten
    # (simulating an upload error, where a part of the file is uploaded but the replica is not registered)
    tmp_file1_name = os.path.basename(tmp_file1)
    if 'SUITE' not in environ or environ['SUITE'] != 'client':
        from rucio.db.sqla import models, session  # Should use a fixture, but setting the session interfers with the generation of rse expressions
        db_session = session.get_session()
        db_session.query(models.RSEFileAssociation).filter_by(name=tmp_file1_name, scope=mock_scope).delete()
        db_session.query(models.ReplicaLock).filter_by(name=tmp_file1_name, scope=mock_scope).delete()
        db_session.query(models.ReplicationRule).filter_by(name=tmp_file1_name, scope=mock_scope).delete()
        db_session.query(models.DidMeta).filter_by(name=tmp_file1_name, scope=mock_scope).delete()
        db_session.query(models.DataIdentifier).filter_by(name=tmp_file1_name, scope=mock_scope).delete()
        db_session.commit()
        tmp_file4 = file_factory.file_generator()
        checksum_tmp_file4 = md5(tmp_file4)
        cmd = 'rucio -v upload --rse {0} --scope {1} --name {2} {3} --register-after-upload'.format(mock_rse, mock_scope.external, tmp_file1_name, tmp_file4)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        print(out)
        print(err)
        assert upload_success_str(path.basename(tmp_file4)) in out or upload_success_str(path.basename(tmp_file4)) in err
        assert checksum_tmp_file4 == [replica for replica in rucio_client.list_replicas(dids=[{'name': tmp_file1_name, 'scope': mock_scope.external}])][0]['md5']

        # try to upload file that already exists on RSE and is already registered -> no overwrite
        cmd = 'rucio -v upload --rse {0} --scope {1} --name {2} {3} --register-after-upload'.format(mock_rse, mock_scope.external, tmp_file1_name, tmp_file4)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0

        print(out)
        print(err)
        remove(tmp_file4)
        assert 'File already registered' in out or 'File already registered' in err


def test_upload_file_guid(file_factory, client_rse_factory, mock_scope, upload_success_str):
    """CLIENT(USER): Rucio upload file with guid"""
    tmp_file1 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    tmp_guid = generate_uuid()
    cmd = f'rucio -v upload --rse {mock_rse} --guid {tmp_guid} --scope {mock_scope} {tmp_file1}'
    exitcode, out, err = execute(cmd)
    remove(tmp_file1)
    upload_string_1 = f"{upload_success_str(path.basename(tmp_file1))}\n"
    assert upload_string_1 in out or upload_string_1 in err
    assert exitcode == 0


def test_upload_file_with_impl(file_factory, client_rse_factory, mock_scope, upload_success_str):
    """CLIENT(USER): Rucio upload file with impl parameter assigned 'posix' value"""
    tmp_file1 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    impl = 'posix'
    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope} --impl {impl} {tmp_file1}'
    exitcode, out, err = execute(cmd)

    remove(tmp_file1)
    upload_string_1 = upload_success_str(path.basename(tmp_file1))
    assert re.search(upload_string_1, err) is not None
    assert exitcode == 0


def test_upload_repeated_file(file_factory, client_rse_factory, mock_scope, upload_success_str):
    """CLIENT(USER): Rucio upload repeated files"""
    # One of the files to upload is already catalogued but was removed
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = path.basename(tmp_file1)
    mock_rse, _ = client_rse_factory.make_posix_rse()

    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # get the rule for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file1_name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    rule = out
    # delete the file from the catalog
    cmd = f"rucio delete-rule {rule}"
    exitcode, out, err = execute(cmd)

    # delete the physical file
    cmd = f"find /tmp/rucio_rse/ -name {tmp_file1_name} |xargs rm"
    exitcode, out, err = execute(cmd)
    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file2}'
    exitcode, out, err = execute(cmd)
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    upload_string_1 = upload_success_str(tmp_file1_name)
    assert upload_string_1 in out or upload_string_1 in err


def test_upload_repeated_file_dataset(file_factory, mock_scope, client_rse_factory, rse_name_generator):
    """CLIENT(USER): Rucio upload repeated files to dataset"""
    # One of the files to upload is already in the dataset
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = tmp_file1.name
    tmp_file3_name = tmp_file3.name
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    # Adding files to a new dataset
    cmd = f'rucio -v upload --rse {tmp_rse} --scope {mock_scope.external} {tmp_file1} {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # upload the files to the dataset
    cmd = f'rucio -v upload --rse {tmp_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file3} {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode != 0  # Temp 1 is already there, throws an error in the exitcode (80)

    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # searching for the file in the new dataset
    cmd = f'rucio list-files {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # tmp_file1 must be in the dataset
    assert re.search(f"{mock_scope.external}:{tmp_file1_name}", out) is not None
    # tmp_file3 must be in the dataset
    assert re.search(f"{mock_scope.external}:{tmp_file3_name}", out) is not None


def test_upload_file_dataset(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio upload files to dataset"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = tmp_file1.name
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    # Adding files to a new dataset
    cmd = f'rucio -v upload --rse {tmp_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file3} {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # searching for the file in the new dataset
    cmd = f'rucio list-files {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(f"{mock_scope.external}:{tmp_file1_name}", out) is not None


def test_upload_file_dataset_register_after_upload(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio upload files to dataset with file registration after upload"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = tmp_file1.name
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    rse_name, _ = client_rse_factory.make_posix_rse()
    # Adding files to a new dataset
    cmd = f'rucio -v upload --register-after-upload --rse {rse_name} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file3} {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # searching for the file in the new dataset
    cmd = f'rucio list-files {tmp_dsn}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(f"{mock_scope.external}:{tmp_file1_name}", out) is not None


def test_upload_adds_md5digest(rucio_client, file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Upload Checksums"""
    # user has a file to upload
    filename = file_factory.file_generator()
    temp_rse, _ = client_rse_factory.make_posix_rse()
    tmp_file1_name = filename.name
    file_md5 = md5(filename)
    # user uploads file
    cmd = f'rucio -v upload --rse {temp_rse} --scope {mock_scope.external} {filename}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # When inspecting the metadata of the new file the user finds the md5 checksum
    meta = rucio_client.get_metadata(scope=mock_scope.external, name=tmp_file1_name)
    remove(filename)
    assert 'md5' in meta
    assert meta['md5'] == file_md5


def test_upload_expiration_date(file_factory, client_rse_factory, mock_scope, upload_success_str):
    """CLIENT(USER): Rucio upload files"""
    tmp_file = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2021-10-10-20:00:00 --lifetime 20000  {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "--lifetime and --expiration-date cannot be specified at the same time." in err

    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2021----10-10-20:00:00 {tmp_file}'
    exitcode, out, err = execute(cmd)

    assert exitcode != 0
    assert "does not match format '%Y-%m-%d-%H:%M:%S'" in err

    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2021-10-10-20:00:00 {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "The specified expiration date should be in the future!" in err

    cmd = f'rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2030-10-10-20:00:00 {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    remove(tmp_file)
    upload_string = upload_success_str(path.basename(tmp_file))
    assert upload_string in out or upload_string in err


def test_create_dataset(mock_scope, rse_name_generator):
    """CLIENT(USER): Rucio add dataset"""
    tmp_name = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    cmd = 'rucio add-dataset ' + tmp_name
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search('Added ' + tmp_name, out) is not None


def test_add_files_to_dataset(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio add files to dataset"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_dataset = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    mock_rse, _ = client_rse_factory.make_posix_rse()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(mock_rse, mock_scope.external, tmp_file1, tmp_file2)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # create dataset
    cmd = 'rucio add-dataset ' + tmp_dataset
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # add files to dataset
    cmd = f'rucio attach {tmp_dataset} {mock_scope.external}:{tmp_file1.name} {mock_scope.external}:{tmp_file2.name}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # find the added files
    cmd = 'rucio list-files ' + tmp_dataset
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(tmp_file1.name, out) is not None


def test_download_file(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download files"""
    tmp_file1 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # download files
    cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(mock_scope.external, tmp_file1.name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = 'ls /tmp/'    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is not None

    tmp_file1 = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # download files
    cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(mock_scope.external, tmp_file1.name + '*')  # triming '/tmp/' from filename
    exitcode, out, err = execute(cmd)
    print(out, err)
    # search for the files with ls
    cmd = 'ls /tmp/'    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is not None


def test_download_pfn(file_factory, rucio_client, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download files"""
    tmp_file1 = file_factory.file_generator()
    name = os.path.basename(tmp_file1)
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # download files
    replica_pfn = list(rucio_client.list_replicas([{'scope': mock_scope.external, 'name': name}]))[0]['rses'][mock_rse][0]
    cmd = 'rucio -v download --rse {0} --pfn {1} {2}:{3}'.format(mock_rse, replica_pfn, mock_scope.external, name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search('Total files.*1', out) is not None


def test_download_file_with_impl(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download files with impl parameter assigned 'posix' value"""
    tmp_file1 = file_factory.file_generator()
    impl = 'posix'
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(mock_rse, mock_scope.external, impl, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # download files
    cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2}'.format(mock_scope.external, tmp_file1.name, impl)  # triming '/tmp/' from filename
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = 'ls /tmp/'    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is not None

    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(mock_rse, mock_scope.external, impl, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # download files
    cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2}'.format(mock_scope.external, tmp_file1.name + '*', impl)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = 'ls /tmp/'    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(tmp_file1.name, out) is not None


@pytest.mark.noparallel(reason='fails when run in parallel')
def test_download_no_subdir(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download files with --no-subdir and check that files already found locally are not replaced"""
    tmp_file = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # download files with --no-subdir
    cmd = 'rucio -v download --no-subdir --dir /tmp {0}:{1}'.format(mock_scope.external, tmp_file.name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = 'ls /tmp/'    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert tmp_file.name in out
    # download again with --no-subdir
    cmd = 'rucio -v download --no-subdir --dir /tmp {0}:{1}'.format(mock_scope.external, tmp_file.name)  # triming '/tmp/' from filename
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(r'Downloaded files:\s+0', out) is not None
    assert re.search(r'Files already found locally:\s+1', out) is not None


def test_download_filter(file_factory, mock_scope, client_rse_factory):
    """CLIENT(USER): Rucio download with filter options"""
    # Use filter option to download file with wildcarded name
    tmp_file1 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse()
    scope_name = mock_scope.external
    uuid = generate_uuid()
    cmd = 'rucio upload --rse {0} --scope {1} --guid {2} {3}'.format(mock_rse, scope_name, uuid, tmp_file1)
    exitcode, out, err = execute(cmd)
    remove(tmp_file1)

    # Expected to fail
    wrong_guid = generate_uuid()
    cmd = 'rucio -v download --dir /tmp {0}:{1} --filter guid={2}'.format(scope_name, '*', wrong_guid)
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    cmd = 'ls /tmp/{0}'.format(scope_name)
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is None

    # Correct guuid
    cmd = 'rucio -v download --dir /tmp {0}:{1} --filter guid={2}'.format(scope_name, '*', uuid)
    exitcode, out, err = execute(cmd)
    cmd = 'ls /tmp/{0}'.format(scope_name)
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is not None

    # Only use filter option to download file
    tmp_file1 = file_factory.file_generator()
    uuid = generate_uuid()
    cmd = 'rucio upload --rse {0} --scope {1} --guid {2} {3}'.format(mock_rse, scope_name, uuid, tmp_file1)
    exitcode, out, err = execute(cmd)
    remove(tmp_file1)

    # Expected to fail
    wrong_guid = generate_uuid()
    cmd = 'rucio -v download --dir /tmp --scope {0} --filter guid={1}'.format(scope_name, wrong_guid)
    exitcode, out, err = execute(cmd)
    cmd = 'ls /tmp/{0}'.format(scope_name)
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is None

    # Using the correct guuid
    cmd = 'rucio -v download --dir /tmp --scope {0} --filter guid={1}'.format(scope_name, uuid)
    exitcode, out, err = execute(cmd)
    cmd = 'ls /tmp/{0}'.format(scope_name)
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is not None

    # Only use filter option to download dataset
    tmp_file1 = file_factory.file_generator()
    dataset_name = 'dataset_%s' % generate_uuid()
    cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(mock_rse, scope_name, tmp_file1, dataset_name)
    exitcode, out, err = execute(cmd)
    remove(tmp_file1)

    cmd = 'rucio download --dir /tmp --scope {0} --filter created_before=1900-01-01T00:00:00.000Z'.format(scope_name)
    exitcode, out, err = execute(cmd)
    cmd = 'ls /tmp/{0}'.format(dataset_name)
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file1.name, out) is None

    cmd = 'rucio download --dir /tmp --scope {0} --filter created_after=1900-01-01T00:00:00.000Z'.format(scope_name)
    exitcode, out, err = execute(cmd)
    print(exitcode)
    cmd = 'ls /tmp/{0}'.format(dataset_name)
    exitcode, out, err = execute(cmd)
    # TODO: https://github.com/rucio/rucio/issues/2926 !
    # assert re.search(tmp_file1.name, out) is not None

    # Use filter option to download dataset with wildcarded name
    tmp_file1 = file_factory.file_generator()
    cmd = 'rucio upload --rse {0} --scope {1} {2} {1}:{3}'.format(mock_rse, scope_name, tmp_file1, dataset_name)
    exitcode, out, err = execute(cmd)
    remove(tmp_file1)

    cmd = 'rucio download --dir /tmp {0}:{1} --filter created_before=1900-01-01T00:00:00.000Z'.format(scope_name, dataset_name[0:-1] + '*')
    exitcode, out, err = execute(cmd)
    print(out, err)
    cmd = 'ls /tmp/{0}'.format(dataset_name)
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert re.search(tmp_file1.name, out) is None

    cmd = 'rucio download --dir /tmp {0}:{1} --filter created_after=1900-01-01T00:00:00.000Z'.format(scope_name, dataset_name[0:-1] + '*')
    exitcode, out, err = execute(cmd)
    print(out, err)
    cmd = 'ls /tmp/{0}'.format(dataset_name)
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert re.search(tmp_file1.name, out) is not None


def test_download_timeout_options_accepted(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download timeout options """
    tmp_file1 = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # download files
    cmd = 'rucio download --dir /tmp --transfer-timeout 3 --transfer-speed-timeout 1000 {0}:{1}'.format(mock_scope.external, tmp_file1.name)  # triming '/tmp/' from filename
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert 'successfully downloaded' in err

    # Check that PFN the transfer-speed-timeout option is not accepted for --pfn
    cmd = 'rucio -v download --rse {0} --transfer-speed-timeout 1 --pfn http://a.b.c/ {1}:{2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "Download with --pfn doesn't support --transfer-speed-timeout" in err


def test_download_metalink_file(file_factory, rucio_client, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download with metalink file"""
    metalink_file_path = generate_uuid()
    scope = mock_scope.external

    # Use filter and metalink option
    cmd = 'rucio download --scope mock --filter size=1 --metalink=test'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert 'Arguments filter and metalink cannot be used together' in err

    # Use did and metalink option
    cmd = 'rucio download --metalink=test mock:test'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert 'Arguments dids and metalink cannot be used together' in err

    # Download only with metalink file
    tmp_file = file_factory.file_generator()
    tmp_file_name = tmp_file.name
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, scope, tmp_file)
    exitcode, out, err = execute(cmd)
    replica_file = rucio_client.list_replicas([{'scope': scope, 'name': tmp_file_name}], metalink=True)
    with open(metalink_file_path, 'w+') as metalink_file:
        metalink_file.write(replica_file)
    cmd = 'rucio download --dir /tmp --metalink {0}'.format(metalink_file_path)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert '{} successfully downloaded'.format(tmp_file_name) in err
    assert re.search('Total files.*1', out) is not None
    remove(metalink_file_path)
    cmd = 'ls /tmp/{0}'.format(scope)
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file_name, out) is not None


def test_download_succeeds_md5only(file_factory, rucio_client, client_rse_factory, vo, mock_scope):
    """CLIENT(USER): Rucio download succeeds MD5 only"""
    # user has a file to upload
    filename = file_factory.file_generator()
    file_md5 = md5(filename)
    filesize = stat(filename).st_size
    lfn = {'name': filename.name, 'scope': mock_scope.external, 'bytes': filesize, 'md5': file_md5}
    # user uploads file
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rucio_client.add_replicas(files=[lfn], rse=mock_rse)
    rse_settings = rsemgr.get_rse_info(rse=mock_rse, vo=vo)
    protocol = rsemgr.create_protocol(rse_settings, 'write')
    protocol.connect()
    pfn = list(protocol.lfns2pfns(lfn).values())[0]
    protocol.put(filename.name, pfn, str(filename.parent))
    protocol.close()
    remove(filename)
    # download files
    cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(mock_scope.external, filename.name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = 'ls /tmp/{0}'.format(mock_scope.external)    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(filename.name, out) is not None


def test_download_fails_badmd5(file_factory, rucio_client, client_rse_factory, mock_scope, vo):
    """CLIENT(USER): Rucio download fails on MD5 mismatch"""
    # user has a file to upload
    filename = file_factory.file_generator()
    file_md5 = md5(filename)
    filesize = stat(filename).st_size
    lfn = {'name': filename.name, 'scope': mock_scope.external, 'bytes': filesize, 'md5': '0123456789abcdef0123456789abcdef'}
    # user uploads file
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rucio_client.add_replicas(files=[lfn], rse=mock_rse)
    rse_settings = rsemgr.get_rse_info(rse=mock_rse, vo=vo)
    protocol = rsemgr.create_protocol(rse_settings, 'write')
    protocol.connect()
    pfn = list(protocol.lfns2pfns(lfn).values())[0]
    protocol.put(filename.name, pfn, str(filename.parent))
    protocol.close()
    remove(filename)

    # download file
    cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(mock_scope.external, filename.name)
    exitcode, out, err = execute(cmd)
    assert exitcode != 0

    report = r'Local\ checksum\:\ {0},\ Rucio\ checksum\:\ 0123456789abcdef0123456789abcdef'.format(file_md5)
    print('searching', report, 'in', err)
    assert re.search(report, err) is not None

    # The file should not exist
    cmd = 'ls /tmp/'    # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(filename.name, out) is None


def test_download_dataset(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download dataset"""
    tmp_file1 = file_factory.file_generator()
    tmp_dataset = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # create dataset
    cmd = 'rucio add-dataset ' + tmp_dataset
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # add files to dataset
    cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dataset, mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    os.remove(tmp_file1)

    # download dataset
    cmd = 'rucio -v download --dir /tmp {0}'.format(tmp_dataset)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    search = '{0} successfully downloaded'.format(tmp_file1.name)
    assert re.search(search, err) is not None


def test_download_file_check_by_size(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio download files"""
    tmp_file1 = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    cmd = 'rucio -v download --dir /tmp {0}:{1}'.format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    cmd = 'echo "dummy" >> /tmp/{}/{}'.format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    # Download file again and check for mismatch
    cmd = 'rucio -v download --check-local-with-filesize-only --dir /tmp {0}:{1}'.format(mock_scope.external, tmp_file1.name)  # triming '/tmp/' from filename

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    assert "File with same name exists locally, but filesize mismatches" in err


def test_list_blocklisted_replicas(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio list replicas"""
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio-admin rse add-protocol --hostname blocklistreplica --scheme file --prefix /rucio --port 0 --impl rucio.rse.protocols.posix.Default ' \
        '--domain-json \'{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}}\' %s' % tmp_rse

    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add files
    tmp_file1 = file_factory.file_generator()
    file_name = tmp_file1.name
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(tmp_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # create dataset
    tmp_dataset = mock_scope.external + ':DSet' + rse_name_generator()
    cmd = 'rucio add-dataset ' + tmp_dataset
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add files to dataset
    cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dataset, mock_scope.external, file_name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # Listing the replica should work before blocklisting the RSE
    cmd = 'rucio list-file-replicas {}'.format(tmp_dataset)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert tmp_rse in out

    # Blocklist the rse
    cmd = 'rucio-admin rse update --rse {} --setting availability_read --value False'.format(tmp_rse)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert not err

    # list-file-replicas should, by default, list replicas from blocklisted rses
    cmd = 'rucio list-file-replicas {}'.format(tmp_dataset)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert tmp_rse in out


def test_create_rule(file_factory, rse_name_generator, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Rucio add rule"""
    tmp_file1 = file_factory.file_generator()

    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add rse
    tmp_rse = rse_name_generator()
    cmd = 'rucio-admin rse add {0}'.format(tmp_rse)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)
    exitcode, out, err = execute(cmd)

    # add rules
    cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    rule = out[:-1]  # triming new line character
    assert re.match(r'^\w+$', rule)

    # check if rule exist for the file
    cmd = "rucio list-rules {0}:{1}".format(mock_scope.external, tmp_file1.name)
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(rule, out) is not None


def test_create_rule_delayed(file_factory, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Rucio add rule delayed"""
    tmp_file1 = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)
    exitcode, out, err = execute(cmd)

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()

    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)

    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASRULEDELAYED'.format(tmp_rse)
    exitcode, out, err = execute(cmd)

    # try adding rule with an incorrect delay-injection. Must fail
    cmd = "rucio add-rule --delay-injection asdsaf {0}:{1} 1 'spacetoken=ATLASRULEDELAYED'".format(mock_scope.external, tmp_file1.name)
    exitcode, out, err = execute(cmd)
    assert err
    assert exitcode != 0
    cmd = "rucio add-rule --delay-injection 3600 {0}:{1} 1 'spacetoken=ATLASRULEDELAYED'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert not err
    rule = out[:-1]  # triming new line character
    cmd = "rucio rule-info {0}".format(rule)

    exitcode, out, err = execute(cmd)
    out_lines = out.splitlines()
    assert any(re.match(r'State:.* INJECT', line) for line in out_lines)
    assert any(re.match(r'Locks OK/REPLICATING/STUCK:.* 0/0/0', line) for line in out_lines)
    # Check that "Created at" is approximately 3600 seconds in the future
    [created_at_line] = filter(lambda x: "Created at" in x, out_lines)
    created_at = re.search(r'Created at:\s+(\d.*\d)$', created_at_line).group(1)
    created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
    assert datetime.utcnow() + timedelta(seconds=3550) < created_at < datetime.utcnow() + timedelta(seconds=3650)


def test_delete_rule(file_factory, rse_name_generator, client_rse_factory, rucio_client, mock_scope):
    """CLIENT(USER): rule deletion"""
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rucio_client.set_local_account_limit('root', mock_rse, -1)
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse = rse_name_generator()
    cmd = 'rucio-admin rse add {0}'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out)
    rucio_client.set_local_account_limit('root', tmp_rse, -1)

    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASDELETERULE'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rules
    cmd = "rucio add-rule {0}:{1} 1 'spacetoken=ATLASDELETERULE'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(err)
    print(out)
    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    (rule1, rule2) = out.split()
    # delete the rules for the file
    cmd = "rucio delete-rule {0}".format(rule1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    cmd = "rucio delete-rule {0}".format(rule2)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # search for the file
    cmd = "rucio list-dids --filter type==all {0}:{1}".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert 5 == len(out.splitlines())


def test_move_rule(file_factory, rse_name_generator, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Rucio move rule"""
    tmp_file1 = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse = rse_name_generator()
    cmd = 'rucio-admin rse add {0}'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out)
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rules
    cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out)
    assert not err
    rule = out[:-1]  # triming new line character
    assert re.match(r'^\w+$', rule)

    # move rule
    new_rule_expr = "'spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD'"
    cmd = "rucio move-rule {} {}".format(rule, new_rule_expr)

    exitcode, out, err = execute(cmd)
    print(out)
    assert not err
    new_rule = out[:-1]  # triming new line character

    # check if rule exist for the file
    cmd = "rucio list-rules {0}:{1}".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert re.search(new_rule, out) is not None


def test_move_rule_with_arguments(file_factory, rse_name_generator, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Rucio move rule"""
    tmp_file1 = file_factory.file_generator()
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse = rse_name_generator()
    cmd = 'rucio-admin rse add {0}'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out)
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    # add quota
    rucio_client.set_local_account_limit('root', tmp_rse, -1)
    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASSCRATCHDISK'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rules
    cmd = "rucio add-rule {0}:{1} 3 'spacetoken=ATLASSCRATCHDISK'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out)
    assert not err
    rule = out[:-1]  # triming new line character
    assert re.match(r'^\w+$', rule)
    # move rule
    new_rule_expr = "spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD"
    new_rule_activity = "No User Subscription"
    new_rule_source_replica_expression = "spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD"
    cmd = "rucio move-rule --activity '{}' --source-replica-expression '{}' {} '{}'".format(new_rule_activity, new_rule_source_replica_expression, rule, new_rule_expr)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert not err
    new_rule_id = out[:-1]  # triming new line character

    # check if rule exist for the file
    cmd = "rucio list-rules {0}:{1}".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert re.search(new_rule_id, out) is not None
    # check updated rule information
    cmd = "rucio rule-info {0}".format(new_rule_id)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert new_rule_activity in out
    assert new_rule_source_replica_expression in out


def test_add_file_twice(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Add file twice"""
    tmp_file1 = file_factory.file_generator()
    # add file twice
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    assert re.search("File {0}:{1} successfully uploaded on the storage".format(mock_scope.external, tmp_file1.name), out) is None


def test_add_delete_add_file(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): Add/Delete/Add"""
    tmp_file1 = file_factory.file_generator()
    # add file
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # get the rule for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    rule = out
    # delete the file from the catalog
    cmd = "rucio delete-rule {0}".format(rule)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # delete the fisical file
    cmd = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # modify the file to avoid same checksum
    cmd = "echo 'delta' >> {0}".format(tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add the same file
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert re.search("File {0}:{1} successfully uploaded on the storage".format(mock_scope.external, tmp_file1.name), out) is None


def test_attach_files_dataset(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio attach files to dataset"""
    # Attach files to a dataset using the attach method
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    mock_rse, _ = client_rse_factory.make_posix_rse()
    # Adding files to a new dataset
    cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(mock_rse, mock_scope.external, tmp_file1, tmp_dsn)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    # upload the files
    cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(mock_rse, mock_scope.external, tmp_file2, tmp_file3)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # attach the files to the dataset
    cmd = 'rucio attach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, mock_scope.external, tmp_file2.name, tmp_file3.name)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    # searching for the file in the new dataset
    cmd = 'rucio list-files {0}'.format(tmp_dsn)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    # tmp_file2 must be in the dataset
    assert re.search("{0}:{1}".format(mock_scope.external, tmp_file2.name), out) is not None
    # tmp_file3 must be in the dataset
    assert re.search("{0}:{1}".format(mock_scope.external, tmp_file3.name), out) is not None


def test_detach_files_dataset(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio detach files to dataset"""
    # Attach files to a dataset using the attach method
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    # Adding files to a new dataset
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {5}'.format(mock_rse, mock_scope.external, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # detach the files to the dataset
    cmd = 'rucio detach {0} {1}:{2} {1}:{3}'.format(tmp_dsn, mock_scope.external, tmp_file2.name, tmp_file3.name)  # triming '/tmp/' from filenames

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    # searching for the file in the new dataset
    cmd = 'rucio list-files {0}'.format(tmp_dsn)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    # tmp_file1 must be in the dataset
    assert re.search("{0}:{1}".format(mock_scope.external, tmp_file1.name), out) is not None
    # tmp_file3 must be in the dataset
    assert re.search("{0}:{1}".format(mock_scope.external, tmp_file3.name), out) is None


def test_attach_file_twice(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio attach a file twice"""
    # Attach files to a dataset using the attach method
    tmp_file1 = file_factory.file_generator()
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    mock_rse, _ = client_rse_factory.make_posix_rse()
    # Adding files to a new dataset
    cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(mock_rse, mock_scope.external, tmp_file1, tmp_dsn)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    remove(tmp_file1)
    # attach the files to the dataset
    cmd = 'rucio attach {0} {1}:{2}'.format(tmp_dsn, mock_scope.external, tmp_file1.name)  # triming '/tmp/' from filenames

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    assert re.search("The file already exists", err) is not None


def test_attach_dataset_twice(did_client, mock_scope):
    """ CLIENT(USER): Rucio attach a dataset twice """
    container = 'container_%s' % generate_uuid()
    dataset = 'dataset_%s' % generate_uuid()
    did_client.add_container(scope=mock_scope.external, name=container)
    did_client.add_dataset(scope=mock_scope.external, name=dataset)

    # Attach dataset to container
    cmd = 'rucio attach {0}:{1} {0}:{2}'.format(mock_scope.external, container, dataset)
    exitcode, out, err = execute(cmd)

    # Attach again
    cmd = 'rucio attach {0}:{1} {0}:{2}'.format(mock_scope.external, container, dataset)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    assert re.search("Data identifier already added to the destination content", err) is not None


def test_detach_non_existing_file(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Rucio detach a non existing file"""
    tmp_file1 = file_factory.file_generator()
    tmp_dsn = mock_scope.external + ':DSet' + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    mock_rse, _ = client_rse_factory.make_posix_rse()
    # Adding files to a new dataset
    cmd = 'rucio upload --rse {0} --scope {1} {2} {3}'.format(mock_rse, mock_scope.external, tmp_file1, tmp_dsn)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    remove(tmp_file1)
    # attach the files to the dataset
    cmd = 'rucio detach {0} {1}:{2}'.format(tmp_dsn, mock_scope.external, 'file_ghost')  # triming '/tmp/' from filenames

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    assert re.search("Data identifier not found.", err) is not None


@pytest.mark.dirty
def test_list_did_recursive():
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
def test_attach_many_dids(rse_name_generator, mock_scope, did_client):
    """ CLIENT(USER): Rucio attach many (>1000) DIDs """
    # Setup data for CLI check
    tmp_dsn_name = 'Container' + rse_name_generator()
    tmp_dsn_did = mock_scope.external + ':' + tmp_dsn_name
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name, did_type='CONTAINER')

    files = [{'name': 'dsn_%s' % generate_uuid(), 'scope': mock_scope.external, 'type': 'DATASET'} for i in range(0, 1500)]
    did_client.add_dids(files[:1000])
    did_client.add_dids(files[1000:])

    # Attaching over 1000 DIDs with CLI
    cmd = 'rucio attach {0}'.format(tmp_dsn_did)
    for tmp_file in files:
        cmd += ' {0}:{1}'.format(tmp_file['scope'], tmp_file['name'])
    exitcode, out, err = execute(cmd)
    print(out)
    print(err)

    # Checking if the execution was successfull and if the DIDs belong together
    assert re.search('DIDs successfully attached', out) is not None
    cmd = 'rucio list-content {0}'.format(tmp_dsn_did)

    exitcode, out, err = execute(cmd)
    # first dataset must be in the container
    assert re.search("{0}:{1}".format(mock_scope.external, files[0]['name']), out) is not None
    # last dataset must be in the container
    assert re.search("{0}:{1}".format(mock_scope.external, files[-1]['name']), out) is not None

    # Setup data with file
    did_file_path = 'list_dids.txt'
    files = [{'name': 'dsn_%s' % generate_uuid(), 'scope': mock_scope.external, 'type': 'DATASET'} for i in range(0, 1500)]
    did_client.add_dids(files[:1000])
    did_client.add_dids(files[1000:])

    with open(did_file_path, 'w') as did_file:
        for file in files:
            did_file.write(file['scope'] + ':' + file['name'] + '\n')
        did_file.close()

    # Attaching over 1000 files per file
    cmd = 'rucio attach {0} -f {1}'.format(tmp_dsn_did, did_file_path)

    exitcode, out, err = execute(cmd)
    print(out)
    print(err)
    remove(did_file_path)

    # Checking if the execution was successfull and if the DIDs belong together
    assert re.search('DIDs successfully attached', out) is not None
    cmd = 'rucio list-content {0}'.format(tmp_dsn_did)

    exitcode, out, err = execute(cmd)
    # first file must be in the dataset
    assert re.search("{0}:{1}".format(mock_scope.external, files[0]['name']), out) is not None
    # last file must be in the dataset
    assert re.search("{0}:{1}".format(mock_scope.external, files[-1]['name']), out) is not None


@pytest.mark.dirty
def test_attach_many_dids_twice(mock_scope, did_client):
    """ CLIENT(USER): Attach many (>1000) DIDs twice """
    # Setup data for CLI check
    container_name = 'container' + generate_uuid()
    container = mock_scope.external + ':' + container_name
    did_client.add_did(scope=mock_scope.external, name=container_name, did_type='CONTAINER')

    datasets = [{'name': 'dsn_%s' % generate_uuid(), 'scope': mock_scope.external, 'type': 'DATASET'} for i in range(0, 1500)]
    did_client.add_dids(datasets[:1000])
    did_client.add_dids(datasets[1000:])

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
    new_dataset = {'name': 'dsn_%s' % generate_uuid(), 'scope': mock_scope.external, 'type': 'DATASET'}
    datasets.append(new_dataset)
    did_client.add_did(scope=mock_scope.external, name=new_dataset['name'], did_type='DATASET')
    cmd = 'rucio attach {0}'.format(container)
    for dataset in datasets:
        cmd += ' {0}:{1}'.format(dataset['scope'], dataset['name'])
    exitcode, out, err = execute(cmd)
    assert re.search("DIDs successfully attached", out) is not None
    cmd = 'rucio list-content {0}'.format(container)
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, new_dataset['name']), out) is not None


@pytest.mark.noparallel(reason='might override global RSE settings')
def test_import_data(rse_name_generator, rse_client):
    """ CLIENT(ADMIN): Import data into rucio"""
    file_path = 'data_import.json'
    rses = {rse['rse']: rse for rse in rse_client.list_rses()}
    rses[rse_name_generator()] = {'country_name': 'test'}
    data = {'rses': rses}
    with open(file_path, 'w+') as file:
        file.write(render_json(**data))
    cmd = 'rucio-admin data import {0}'.format(file_path)
    exitcode, out, err = execute(cmd)
    assert re.search('Data successfully imported', out) is not None
    remove(file_path)


@pytest.mark.noparallel(reason='fails when run in parallel')
def test_export_data():
    """ CLIENT(ADMIN): Export data from rucio"""
    file_path = 'data_export.json'
    cmd = 'rucio-admin data export {0}'.format(file_path)
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert re.search('Data successfully exported', out) is not None
    remove(file_path)


@pytest.mark.dirty
@pytest.mark.noparallel(reason='fails when run in parallel')
def test_set_tombstone(client_rse_factory, rucio_client):
    """ CLIENT(ADMIN): set a tombstone on a replica. """
    # Set tombstone on one replica
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rse = mock_rse
    scope = 'mock'
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
    cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
    exitcode, out, err = execute(cmd)
    assert re.search('Set tombstone successfully', err) is not None

    # Set tombstone on locked replica
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
    rucio_client.add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
    cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
    exitcode, out, err = execute(cmd)
    assert re.search('Replica is locked', err) is not None

    # Set tombstone on not found replica
    name = generate_uuid()
    cmd = 'rucio-admin replicas set-tombstone {0}:{1} --rse {2}'.format(scope, name, rse)
    exitcode, out, err = execute(cmd)
    assert re.search('Replica not found', err) is not None


@pytest.mark.noparallel(reason='modifies account limit on pre-defined RSE')
def test_list_account_limits(rucio_client, client_rse_factory):
    """ CLIENT (USER): list account limits. """
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rse = mock_rse
    rse_exp = f'MOCK3|{rse}'
    account = 'root'
    local_limit = 10
    global_limit = 20
    rucio_client.set_local_account_limit(account, rse, local_limit)
    rucio_client.set_global_account_limit(account, rse_exp, global_limit)
    cmd = 'rucio list-account-limits {0}'.format(account)
    exitcode, out, err = execute(cmd)
    assert re.search('.*{0}.*{1}.*'.format(rse, local_limit), out) is not None
    assert re.search('.*{0}.*{1}.*'.format(rse_exp, global_limit), out) is not None
    cmd = 'rucio list-account-limits --rse {0} {1}'.format(rse, account)
    exitcode, out, err = execute(cmd)
    assert re.search('.*{0}.*{1}.*'.format(rse, local_limit), out) is not None
    assert re.search('.*{0}.*{1}.*'.format(rse_exp, global_limit), out) is not None
    rucio_client.set_local_account_limit(account, rse, -1)
    rucio_client.set_global_account_limit(account, rse_exp, -1)


@pytest.mark.noparallel(reason='modifies account limit on pre-defined RSE')
@pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'client', reason='uses abacus daemon and core functions')
def test_list_account_usage(root_account, rucio_client, client_rse_factory):
    """ CLIENT (USER): list account usage. """
    from rucio.db.sqla import session, models
    from rucio.core.account_counter import increase
    from rucio.daemons.abacus import account as abacus_account
    mock_rse, mock_rse_id = client_rse_factory.make_posix_rse()
    db_session = session.get_session()
    db_session.query(models.AccountUsage).delete()
    db_session.query(models.AccountLimit).delete()
    db_session.query(models.AccountGlobalLimit).delete()
    db_session.query(models.UpdatedAccountCounter).delete()
    db_session.commit()
    rse = mock_rse
    rse_id = mock_rse_id
    rse_exp = f'MOCK|{rse}'
    account = 'root'
    usage = 4
    local_limit = 10
    local_left = local_limit - usage
    global_limit = 20
    global_left = global_limit - usage
    rucio_client.set_local_account_limit(account, rse, local_limit)
    rucio_client.set_global_account_limit(account, rse_exp, global_limit)
    increase(rse_id, root_account, 1, usage)
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
    rucio_client.set_local_account_limit(account, rse, -1)
    rucio_client.set_global_account_limit(account, rse_exp, -1)


def test_get_set_delete_limits_rse(account_name_generator, client_rse_factory):
    """CLIENT(ADMIN): Get, set and delete RSE limits"""
    name = generate_uuid()
    value = random.randint(0, 100000)
    name2 = generate_uuid()
    value2 = random.randint(0, 100000)
    mock_rse, _ = client_rse_factory.make_posix_rse()
    name3 = generate_uuid()
    value3 = account_name_generator()
    cmd = 'rucio-admin rse set-limit %s %s %s' % (mock_rse, name, value)
    execute(cmd)
    cmd = 'rucio-admin rse set-limit %s %s %s' % (mock_rse, name2, value2)
    execute(cmd)
    cmd = 'rucio-admin rse info %s' % mock_rse
    exitcode, out, err = execute(cmd)
    assert re.search("{0}: {1}".format(name, value), out) is not None
    assert re.search("{0}: {1}".format(name2, value2), out) is not None
    new_value = random.randint(100001, 999999999)
    cmd = 'rucio-admin rse set-limit %s %s %s' % (mock_rse, name, new_value)
    execute(cmd)
    cmd = 'rucio-admin rse info %s' % mock_rse
    exitcode, out, err = execute(cmd)
    assert re.search("{0}: {1}".format(name, new_value), out) is not None
    assert re.search("{0}: {1}".format(name, value), out) is None
    assert re.search("{0}: {1}".format(name2, value2), out) is not None
    cmd = 'rucio-admin rse delete-limit %s %s' % (mock_rse, name)
    execute(cmd)
    cmd = 'rucio-admin rse info %s' % mock_rse
    exitcode, out, err = execute(cmd)
    assert re.search("{0}: {1}".format(name, new_value), out) is None
    assert re.search("{0}: {1}".format(name2, value2), out) is not None
    cmd = 'rucio-admin rse delete-limit %s %s' % (mock_rse, name)
    exitcode, out, err = execute(cmd)
    assert re.search('Limit {0} not defined in RSE {1}'.format(name, mock_rse), err) is not None
    cmd = 'rucio-admin rse set-limit %s %s %s' % (mock_rse, name3, value3)
    exitcode, out, err = execute(cmd)
    assert re.search('The RSE limit value must be an integer', err) is not None
    cmd = 'rucio-admin rse info %s' % mock_rse
    exitcode, out, err = execute(cmd)
    assert re.search("{0}: {1}".format(name3, value3), out) is None
    assert re.search("{0}: {1}".format(name2, value2), out) is not None


def test_upload_recursive_ok(file_factory, rse_name_generator, client_rse_factory, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure"""
    mock_rse, _ = client_rse_factory.make_posix_rse()
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
    cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (mock_scope.external, mock_rse, folder)
    execute(cmd)
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder)
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, folder1.split('/')[-1]), out) is not None
    assert re.search("{0}:{1}".format(mock_scope.external, folder2.split('/')[-1]), out) is not None
    assert re.search("{0}:{1}".format(mock_scope.external, folder3.split('/')[-1]), out) is None
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder1.split('/')[-1])
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, folder11.split('/')[-1]), out) is not None
    assert re.search("{0}:{1}".format(mock_scope.external, folder12.split('/')[-1]), out) is None
    assert re.search("{0}:{1}".format(mock_scope.external, folder13.split('/')[-1]), out) is None
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder11.split('/')[-1])
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, file1), out) is not None
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder2.split('/')[-1])
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, file2), out) is not None
    cmd = 'rm -rf %s' % folder
    execute(cmd)


def test_upload_recursive_subfolder(client_rse_factory, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure in a subfolder"""
    mock_rse, _ = client_rse_factory.make_posix_rse()
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
    cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (mock_scope.external, mock_rse, folder1)
    execute(cmd)
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder)
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, folder1.split('/')[-1]), out) is None
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder1.split('/')[-1])
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, folder11.split('/')[-1]), out) is not None
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder11.split('/')[-1])
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, file1), out) is not None
    cmd = 'rm -rf %s' % folder
    execute(cmd)


def test_recursive_empty(client_rse_factory, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure with an empty folder"""
    folder = 'folder_' + generate_uuid()
    folder1 = '%s/folder_%s' % (folder, generate_uuid())
    mock_rse, _ = client_rse_factory.make_posix_rse()
    cmd = 'mkdir %s' % (folder)
    execute(cmd)
    cmd = 'mkdir %s' % (folder1)
    execute(cmd)
    cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (mock_scope.external, mock_rse, folder)
    execute(cmd)
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder)
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, folder1.split('/')[-1]), out) is None
    cmd = 'rm -rf %s' % folder
    execute(cmd)


def test_upload_recursive_only_files(client_rse_factory, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure only with files"""
    mock_rse, _ = client_rse_factory.make_posix_rse()
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
    cmd = 'rucio upload --scope %s --rse %s --recursive %s/' % (mock_scope.external, mock_rse, folder)
    execute(cmd)
    cmd = 'rucio list-content %s:%s' % (mock_scope.external, folder)
    exitcode, out, err = execute(cmd)
    assert re.search("{0}:{1}".format(mock_scope.external, file1), out) is not None
    assert re.search("{0}:{1}".format(mock_scope.external, file2), out) is not None
    assert re.search("{0}:{1}".format(mock_scope.external, file3), out) is not None
    cmd = 'rucio ls %s:%s' % (mock_scope.external, folder)
    exitcode, out, err = execute(cmd)
    assert re.search("DATASET", out) is not None
    cmd = 'rm -rf %s' % folder
    execute(cmd)


def test_deprecated_command_line_args():
    """CLIENT(USER): Warn about deprecated command line args"""
    cmd = 'rucio get --trace_appid 0'

    exitcode, out, err = execute(cmd)
    assert 'Warning: The commandline argument --trace_appid is deprecated! Please use --trace-appid in the future.' in out


def test_rucio_admin_expiration_date_is_deprecated():
    """CLIENT(USER): Warn about deprecated command line args"""
    cmd = 'rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --expiration-date 168 --reason \'test only\''

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert 'Warning: The commandline argument --expiration-date is deprecated! Please use --duration in the future.' in out


def test_rucio_admin_expiration_date_not_defined():
    """CLIENT(USER): Warn about deprecated command line arg"""
    cmd = 'rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --reason \'test only\''

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert err != 0
    assert 'the following arguments are required' in err


def test_rucio_admin_duration_out_of_bounds():
    """CLIENT(USER): Warn about deprecated command line arg"""
    cmd = 'rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --duration 622080000 --reason \'test only\''

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert err != 0
    assert re.search(r'The given duration of 7199 days exceeds the maximum duration of 30 days.', err)


def test_update_rule_cancel_requests_args():
    """CLIENT(USER): update rule cancel requests must have a state defined"""
    cmd = 'rucio update-rule --cancel-requests RULE'
    exitcode, out, err = execute(cmd)
    assert '--stuck or --suspend must be specified when running --cancel-requests' in err
    assert exitcode != 0


def test_update_rule_unset_child_rule(file_factory, rse_name_generator, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): update rule unsets a child rule property"""

    # PREPARING FILE AND RSE
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse()
    tmp_file = file_factory.file_generator()
    tmp_fname = tmp_file.name
    cmd = f'rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert 'ERROR' not in err

    for i in range(2):
        tmp_rse = rse_name_generator()
        cmd = f'rucio-admin rse add {tmp_rse}'
        exitcode, out, err = execute(cmd)
        assert not err

        rucio_client.set_local_account_limit('root', tmp_rse, -1)
        cmd = f'rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value RULELOC{i}'
        exitcode, out, err = execute(cmd)
        assert not err

    # PREPARING THE RULES
    # add rule
    rule_expr = "spacetoken=RULELOC0"
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_fname} 1 '{rule_expr}'"
    exitcode, out, err = execute(cmd)
    assert not err
    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".\
        format(mock_scope.external, tmp_file.name)
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
    cmd = "rucio list-rules {0}:{1}".format(mock_scope.external, tmp_fname)
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
    assert 'ERROR' in err
    assert re.search('Cannot detach child when no such relationship exists', err) is not None


def test_update_rule_no_child_selfassign(file_factory, rse_name_generator, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): do not permit to assign self as own child"""
    mock_rse, _ = client_rse_factory.make_posix_rse()
    tmp_file = file_factory.file_generator()
    tmp_fname = tmp_file.name
    cmd = f'rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert 'ERROR' not in err

    tmp_rse = rse_name_generator()
    cmd = f'rucio-admin rse add {tmp_rse}'
    exitcode, out, err = execute(cmd)
    assert not err

    rucio_client.set_local_account_limit('root', tmp_rse, -1)

    cmd = f'rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value RULELOC'
    exitcode, out, err = execute(cmd)
    assert not err

    # PREPARING THE RULES
    # add rule
    rule_expr = "spacetoken=RULELOC"
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_fname} 1 '{rule_expr}'"
    exitcode, out, err = execute(cmd)
    assert not err

    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".\
        format(mock_scope.external, tmp_file.name)
    exitcode, out, err = execute(cmd)
    parentrule_id, _ = out.split()

    # now for the test
    # TODO: merge this with the other update_rule test from issue #5930
    cmd = f"rucio update-rule --child-rule-id {parentrule_id} {parentrule_id}"
    exitcode, out, err = execute(cmd)
    # TODO: add a more specific assertion here.
    assert err


def test_update_rule_boost_rule_arg(file_factory, rucio_client, client_rse_factory, mock_scope):
    """CLIENT(USER): update a rule with the `--boost_rule` option """
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rucio_client.set_local_account_limit('root', mock_rse, -1)
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse()
    print(out)
    rucio_client.set_local_account_limit('root', tmp_rse, -1)

    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value ATLASDELETERULE'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rules
    cmd = "rucio add-rule {0}:{1} 1 'spacetoken=ATLASDELETERULE'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(err)
    print(out)
    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    (rule1, rule2) = out.split()

    # update the rules
    cmd = "rucio update-rule --boost-rule {0}".format(rule1)

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    print(out, err)
    cmd = "rucio update-rule --boost-rule {0}".format(rule2)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0


def test_rucio_list_file_replicas(file_factory, rse_name_generator, client_rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): List missing file replicas """
    mock_rse, _ = client_rse_factory.make_posix_rse()
    rucio_client.set_local_account_limit('root', mock_rse, -1)
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rse
    tmp_rse = rse_name_generator()
    cmd = 'rucio-admin rse add {0}'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out)
    rucio_client.set_local_account_limit('root', tmp_rse, -1)

    # add rse atributes
    cmd = 'rucio-admin rse set-attribute --rse {0} --key spacetoken --value MARIOSPACEODYSSEY'.format(tmp_rse)

    exitcode, out, err = execute(cmd)
    print(out, err)
    # add rules
    cmd = "rucio add-rule {0}:{1} 1 'spacetoken=MARIOSPACEODYSSEY'".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(err)
    print(out)

    cmd = 'rucio list-file-replicas {0}:{1} --rses "spacetoken=MARIOSPACEODYSSEY" --missing'.format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    assert tmp_file1.name in out


def test_rucio_create_rule_with_0_copies(file_factory, client_rse_factory, mock_scope):
    """CLIENT(USER): The creation of a rule with 0 copies shouldn't be possible."""
    mock_rse, _ = client_rse_factory.make_posix_rse()
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = 'rucio upload --rse {0} --scope {1} {2}'.format(mock_rse, mock_scope.external, tmp_file1)

    exitcode, out, err = execute(cmd)
    print(out, err)

    # Try to add a rules with 0 copies, this shouldn't be possible
    cmd = "rucio add-rule {0}:{1} 0 MOCK".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    print(err)
    print(out)
    assert exitcode != 0
    assert "The number of copies for a replication rule should be greater than 0." in err


def test_add_lifetime_exception(did_client, mock_scope):
    """ CLIENT(USER): Rucio submission of lifetime exception """
    container = 'container_%s' % generate_uuid()
    dataset = 'dataset_%s' % generate_uuid()
    did_client.add_container(scope=mock_scope.external, name=container)
    did_client.add_dataset(scope=mock_scope.external, name=dataset)
    filename = get_tmp_dir() + 'lifetime_exception.txt'
    with open(filename, 'w') as file_:
        file_.write('%s:%s\n' % (mock_scope.external, dataset))

    # Try adding an exception
    cmd = 'rucio add-lifetime-exception --inputfile %s --reason "%s" --expiration %s' % (filename, 'Needed for analysis', '2015-10-30')
    print(cmd)
    exitcode, out, err = execute(cmd)
    print(exitcode, out, err)
    assert exitcode == 0
    assert "Nothing to submit" in err

    with open(filename, 'w') as file_:
        file_.write('%s:%s\n' % (mock_scope.external, dataset))
        file_.write('%s:%s' % (mock_scope.external, container))

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


def test_add_lifetime_exception_large_dids_number(mock_scope):
    """ CLIENT(USER): Check that exceptions with more than 1k DIDs are supported """
    filename = get_tmp_dir() + 'lifetime_exception_many_dids.txt'
    with open(filename, 'w') as file_:
        for _ in range(2000):
            file_.write('%s:%s\n' % (mock_scope.external, generate_uuid()))

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


def test_admin_rse_update_unsupported_option(client_rse_factory):
    """ ADMIN CLIENT: Rse update should throw an unsupported option exception on an unsupported exception."""
    mock_rse, _ = client_rse_factory.make_posix_rse()
    exitcode, out, err = execute("rucio-admin rse update --setting test_with_non_existing_option --value 3 --rse {}".format(mock_rse))
    print(out, err)
    assert exitcode != 0
    assert "Details: The key 'test_with_non_existing_option' does not exist for RSE properties.\n" in err

    exitcode, out, err = execute("rucio-admin rse update --setting country_name --value France --rse {}".format(mock_rse))
    print(out, err)
    assert exitcode == 0
    assert not err


@pytest.mark.parametrize("file_config_mock", [
    {
        "overrides": [
            ("lifetime_model", "cutoff_date", (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d'))
        ]
    }
], indirect=True)
def test_lifetime_cli(did_client, rse_name_generator, mock_scope, file_config_mock):
    """ CLIENT(USER): Check CLI to declare lifetime exceptions """
    # Setup data for CLI check
    tmp_dsn_name = 'container' + rse_name_generator()
    tmp_dsn_did = mock_scope.external + ':' + tmp_dsn_name
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name, did_type='DATASET')
    did_client.set_metadata(scope=mock_scope.external, name=tmp_dsn_name, key='eol_at', value=(datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d'))
    with tempfile.NamedTemporaryFile(mode="w+") as fp:
        fp.write(f'{tmp_dsn_did}\n' * 2)
        fp.seek(0)
        exitcode, out, err = execute("rucio add-lifetime-exception --inputfile %s --reason 'For testing purpose; please ignore.' --expiration 2124-01-01" % fp.name)
        assert 'does not exist' not in err


@pytest.mark.parametrize("file_config_mock", [
    {
        "overrides": [
            ("lifetime_model", "cutoff_date", (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d'))
        ]
    }
], indirect=True)
def test_lifetime_container_resolution(did_client, rse_name_generator, mock_scope, file_config_mock):
    """ CLIENT(USER): Check that the CLI to declare lifetime exceptions resolve contaiers"""
    # Setup data for CLI check
    tmp_dsn_name1 = 'dataset' + rse_name_generator()
    tmp_dsn_name2 = 'dataset' + rse_name_generator()
    tmp_cnt_name = 'container' + rse_name_generator()
    tmp_cnt_did = mock_scope.external + ':' + tmp_cnt_name
    # Create 2 datasets and 1 container and attach dataset to container
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name1, did_type='DATASET')
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name2, did_type='DATASET')
    did_client.add_did(scope=mock_scope.external, name=tmp_cnt_name, did_type='CONTAINER')
    did_client.attach_dids(scope=mock_scope.external, name=tmp_cnt_name, dids=[{'scope': mock_scope.external, 'name': tmp_dsn_name1}, {'scope': mock_scope.external, 'name': tmp_dsn_name2}])
    # Set eol_at for the first dataset but not to the second one
    did_client.set_metadata(scope=mock_scope.external, name=tmp_dsn_name1, key='eol_at', value=(datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d'))

    with tempfile.NamedTemporaryFile(mode="w+") as fp:
        fp.write(f'{tmp_cnt_did}')
        fp.seek(0)
        exitcode, out, err = execute("rucio add-lifetime-exception --inputfile %s --reason 'For testing purpose; please ignore.' --expiration 2124-01-01" % fp.name)
        print(exitcode, out, err)
        assert '%s:%s is not affected by the lifetime model' % (mock_scope.external, tmp_dsn_name2)
        assert '%s:%s will be declared' % (mock_scope.external, tmp_dsn_name1)
