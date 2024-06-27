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
from datetime import datetime, timedelta, timezone
from os import environ, path, remove, stat
from tempfile import NamedTemporaryFile, TemporaryDirectory

import pytest
from sqlalchemy.sql.expression import and_, delete

from rucio.common.utils import generate_uuid, md5, render_json
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import execute


def upload_success_str(x):
    return f"Successfully uploaded file {x}"


def test_rucio_version():
    """CLIENT(USER): Rucio version"""
    cmd = "bin/rucio --version"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "rucio" in out or "rucio" in err


def test_rucio_ping(rucio_client):
    host = rucio_client.host
    """CLIENT(USER): Rucio ping"""
    cmd = f"rucio --host {host} ping"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0


def test_rucio_config_arg():
    """CLIENT(USER): Rucio config argument"""
    cmd = "rucio --config errconfig ping"
    exitcode, _, err = execute(cmd)
    assert exitcode != 0
    assert "Could not load Rucio configuration file" in err and re.match(".*errconfig.*$", err, re.DOTALL)


def test_add_account(account_name_generator):
    """CLIENT(ADMIN): Add account"""
    tmp_val = account_name_generator()
    cmd = f"rucio-admin account add {tmp_val}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert f"Added new account: {tmp_val}\n" == out


def test_whoami():
    """CLIENT(USER): Rucio whoami"""
    cmd = "rucio whoami"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert "account" in out


def test_add_identity(account_name_generator):
    """CLIENT(ADMIN): Add identity"""
    temp_account = account_name_generator()
    cmd = f"rucio-admin account add {temp_account}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert f"Added new account: {temp_account}\n" == out
    cmd = f"rucio-admin identity add --account {temp_account} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Added new identity to account: jdoe@CERN.CH-{temp_account}\n" == out


def test_del_identity(account_name_generator):
    """CLIENT(ADMIN): Test del identity"""
    temp_account = account_name_generator()

    # create account
    cmd = f"rucio-admin account add {temp_account}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0

    # add identity to account
    cmd = f"rucio-admin identity add --account {temp_account} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0

    # delete identity from account
    cmd = f"rucio-admin identity delete --account {temp_account} --type GSS --id jdoe@CERN.CH"
    exitcode, out, _ = execute(cmd)
    assert "Deleted identity: jdoe@CERN.CH\n" == out
    assert exitcode == 0

    # list identities for account
    cmd = f"rucio-admin account list-identities {temp_account}"
    exitcode, out, _ = execute(cmd)
    assert "" == out
    assert exitcode == 0


def test_attributes(account_name_generator):
    """CLIENT(ADMIN): Add/List/Delete attributes"""
    temp_account = account_name_generator()

    # create account
    cmd = f"rucio-admin account add {temp_account}"
    exitcode, _, _ = execute(cmd)
    # add attribute to the account
    cmd = f"rucio-admin account add-attribute {temp_account} --key test_attribute_key --value true"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # list attributes
    cmd = f"rucio-admin account list-attributes {temp_account}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # delete attribute to the account
    cmd = f"rucio-admin account delete-attribute {temp_account} --key test_attribute_key"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0


def test_add_scope(account_name_generator, scope_name_generator):
    """CLIENT(ADMIN): Add scope"""
    temp_scope = scope_name_generator()
    temp_account = account_name_generator()
    cmd = f"rucio-admin account add {temp_account}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    cmd = f"rucio-admin scope add --account {temp_account} --scope {temp_scope}"
    exitcode, out, err = execute(cmd)
    assert f"Added new scope to account: {temp_scope}-{temp_account}\n" == out
    assert exitcode == 0


def test_add_rse(rse_name_generator):
    """CLIENT(ADMIN): Add RSE"""
    temp_rse = rse_name_generator()
    cmd = f"rucio-admin rse add {temp_rse}"
    exitcode, out, _ = execute(cmd)
    assert f"Added new deterministic RSE: {temp_rse}\n" == out
    assert exitcode == 0


def test_add_rse_nondet(rse_name_generator):
    """CLIENT(ADMIN): Add non-deterministic RSE"""
    temp_rse = rse_name_generator()
    cmd = f"rucio-admin rse add --non-deterministic {temp_rse}"
    exitcode, out, _ = execute(cmd)
    assert f"Added new non-deterministic RSE: {temp_rse}\n" == out
    assert exitcode == 0


def test_list_rses(rse_name_generator):
    """CLIENT(ADMIN): List RSEs"""
    temp_rse = rse_name_generator()
    cmd = f"rucio-admin rse add {temp_rse}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    cmd = "rucio-admin rse list"
    exitcode, out, _ = execute(cmd)
    assert temp_rse in out
    assert exitcode == 0


def test_rse_add_distance(rse_name_generator):
    """CLIENT (ADMIN): Add distance to RSE"""
    # add RSEs
    temprse1 = rse_name_generator()
    cmd = f"rucio-admin rse add {temprse1}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    temprse2 = rse_name_generator()
    cmd = f"rucio-admin rse add {temprse2}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0

    # add distance between the RSEs
    cmd = f"rucio-admin rse add-distance --distance 1 --ranking 1 {temprse1} {temprse2}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0

    # add duplicate distance
    exitcode, _, err = execute(cmd)
    assert exitcode != 0
    assert f"Details: Distance from {temprse1} to {temprse2} already exists!\n" in err


def test_rse_delete_distance(rse_name_generator):
    """CLIENT (ADMIN): Delete distance to RSE"""
    # add RSEs
    temp_rse1 = rse_name_generator()
    temp_rse2 = rse_name_generator()

    cmd = f"rucio-admin rse add {temp_rse1}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0

    cmd = f"rucio-admin rse add {temp_rse2}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0

    # add distance between the RSEs
    cmd = f"rucio-admin rse add-distance --distance 1 --ranking 1 {temp_rse1} {temp_rse2}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0

    # delete distance OK
    cmd = f"rucio-admin rse delete-distance {temp_rse1} {temp_rse2}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert f"Deleted distance information from {temp_rse1} to {temp_rse2}." in out

    # delete distance RSE not found
    non_added_rse = rse_name_generator()
    cmd = f"rucio-admin rse delete-distance {temp_rse1} {non_added_rse}"
    exitcode, _, err = execute(cmd)
    assert "RSE does not exist." in err
    assert exitcode != 0


def test_upload_file(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio upload files"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope} {tmp_file1} {tmp_file2} {tmp_file3}"
    exitcode, out, err = execute(cmd)
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


def test_upload_file_register_after_upload(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope, rucio_client, vo, root_account):
    """CLIENT(USER): Rucio upload files with registration after upload"""
    # normal upload
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope} {tmp_file1} {tmp_file2} {tmp_file3}"
    exitcode, out, err = execute(cmd)
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
        from rucio.common.types import InternalScope
        from rucio.db.sqla import models, session

        db_session = session.get_session()
        internal_scope = InternalScope(mock_scope.external, vo)
        for model in [models.RSEFileAssociation, models.ReplicaLock, models.ReplicationRule, models.DidMeta, models.DataIdentifier]:
            stmt = delete(
                model
            ).where(
                and_(
                    model.name == tmp_file1_name,
                    model.scope == internal_scope
                )
            )
            db_session.execute(stmt)
        db_session.commit()
        tmp_file4 = file_factory.file_generator()
        checksum_tmp_file4 = md5(tmp_file4)
        cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --name {tmp_file1_name} {tmp_file4} --register-after-upload"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert upload_success_str(path.basename(tmp_file4)) in out or upload_success_str(path.basename(tmp_file4)) in err
        assert checksum_tmp_file4 == [replica for replica in rucio_client.list_replicas(dids=[{"name": tmp_file1_name, "scope": mock_scope.external}])][0]["md5"]

        # try to upload file that already exists on RSE and is already registered -> no overwrite
        cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --name {tmp_file1_name} {tmp_file4} --register-after-upload"
        exitcode, out, err = execute(cmd)
        assert exitcode != 0

        remove(tmp_file4)
        assert "File already registered" in out or "File already registered" in err


def test_upload_file_guid(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio upload file with guid"""
    tmp_file1 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_guid = generate_uuid()
    cmd = f"rucio -v upload --rse {mock_rse} --guid {tmp_guid} --scope {mock_scope} {tmp_file1}"
    exitcode, _, err = execute(cmd)
    remove(tmp_file1)
    print(err)
    assert upload_success_str(path.basename(tmp_file1)) in err
    assert exitcode == 0


def test_upload_file_with_impl(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio upload file with impl parameter assigned 'posix' value"""
    tmp_file1 = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    impl = "posix"
    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope} --impl {impl} {tmp_file1}"
    exitcode, _, err = execute(cmd)

    remove(tmp_file1)
    upload_string_1 = upload_success_str(path.basename(tmp_file1))
    assert re.search(upload_string_1, err) is not None
    assert exitcode == 0


def test_upload_repeated_file(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio upload repeated files"""
    # One of the files to upload is already catalogued but was removed
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = path.basename(tmp_file1)
    mock_rse, mock_rse_id = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    print(mock_rse)

    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"
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
    print(tmp_file1_name)
    # delete the physical file
    cmd = f"find /test_{mock_rse_id}/{mock_scope.external} -name {tmp_file1_name} |xargs rm"
    exitcode, out, err = execute(cmd)

    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file2}"
    exitcode, out, err = execute(cmd)
    print(out, err)
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    upload_string_1 = upload_success_str(tmp_file1_name)
    assert upload_string_1 in out or upload_string_1 in err


def test_upload_repeated_file_dataset(file_factory, mock_scope, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio upload repeated files to dataset"""
    # One of the files to upload is already in the dataset
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = tmp_file1.name
    tmp_file3_name = tmp_file3.name
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_dsn = mock_scope.external + ":DSet" + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    # Adding files to a new dataset
    cmd = f"rucio -v upload --rse {tmp_rse} --scope {mock_scope.external} {tmp_file1} {tmp_dsn}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # upload the files to the dataset
    cmd = f"rucio -v upload --rse {tmp_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file3} {tmp_dsn}"
    exitcode, out, err = execute(cmd)

    assert exitcode != 0  # Temp 1 is already there, throws an error in the exitcode (80)

    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # searching for the file in the new dataset
    cmd = f"rucio list-files {tmp_dsn}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # tmp_file1 must be in the dataset
    assert re.search(f"{mock_scope.external}:{tmp_file1_name}", out) is not None
    # tmp_file3 must be in the dataset
    assert re.search(f"{mock_scope.external}:{tmp_file3_name}", out) is not None


def test_upload_file_dataset(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope):
    """CLIENT(USER): Rucio upload files to dataset"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = tmp_file1.name
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_dsn = mock_scope.external + ":DSet" + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    # Adding files to a new dataset
    cmd = f"rucio -v upload --rse {tmp_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file3} {tmp_dsn}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # searching for the file in the new dataset
    cmd = f"rucio list-files {tmp_dsn}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert re.search(f"{mock_scope.external}:{tmp_file1_name}", out) is not None


def test_upload_file_dataset_register_after_upload(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope):
    """CLIENT(USER): Rucio upload files to dataset with file registration after upload"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    tmp_file1_name = tmp_file1.name
    tmp_dsn = mock_scope.external + ":DSet" + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    rse_name, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    # Adding files to a new dataset
    cmd = f"rucio -v upload --register-after-upload --rse {rse_name} --scope {mock_scope.external} {tmp_file1} {tmp_file2} {tmp_file3} {tmp_dsn}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # searching for the file in the new dataset
    cmd = f"rucio list-files {tmp_dsn}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert re.search(f"{mock_scope.external}:{tmp_file1_name}", out) is not None


def test_upload_adds_md5digest(rucio_client, file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Upload Checksums"""
    # user has a file to upload
    filename = file_factory.file_generator()
    temp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_file1_name = filename.name
    file_md5 = md5(filename)
    # user uploads file
    cmd = f"rucio -v upload --rse {temp_rse} --scope {mock_scope.external} {filename}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # When inspecting the metadata of the new file the user finds the md5 checksum
    meta = rucio_client.get_metadata(scope=mock_scope.external, name=tmp_file1_name)
    remove(filename)
    assert "md5" in meta
    assert meta["md5"] == file_md5


def test_upload_expiration_date(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio upload files"""
    tmp_file = file_factory.file_generator()
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2021-10-10-20:00:00 --lifetime 20000  {tmp_file}"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "--lifetime and --expiration-date cannot be specified at the same time." in err

    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2021----10-10-20:00:00 {tmp_file}"
    exitcode, out, err = execute(cmd)

    assert exitcode != 0
    assert "does not match format '%Y-%m-%d-%H:%M:%S'" in err

    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2021-10-10-20:00:00 {tmp_file}"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "The specified expiration date should be in the future!" in err

    cmd = f"rucio -v upload --rse {mock_rse} --scope {mock_scope.external} --expiration-date 2030-10-10-20:00:00 {tmp_file}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    remove(tmp_file)
    upload_string = upload_success_str(path.basename(tmp_file))
    assert upload_string in out or upload_string in err


def test_create_dataset(mock_scope, rse_name_generator):
    """CLIENT(USER): Rucio add dataset"""
    tmp_name = mock_scope.external + ":DSet" + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    cmd = "rucio add-dataset " + tmp_name
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert re.search("Added " + tmp_name, out) is not None


def test_add_files_to_dataset(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope):
    """CLIENT(USER): Rucio add files to dataset"""
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_dataset = mock_scope.external + ":DSet" + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    # add files
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1} {tmp_file2}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # create dataset
    cmd = "rucio add-dataset " + tmp_dataset
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # add files to dataset
    cmd = f"rucio attach {tmp_dataset} {mock_scope.external}:{tmp_file1.name} {mock_scope.external}:{tmp_file2.name}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0

    # find the added files
    cmd = "rucio list-files " + tmp_dataset
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert re.search(tmp_file1.name, out) is not None


def test_download_file(did_factory, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download files"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)

    tmp_dir = TemporaryDirectory()
    download_dir = tmp_dir.name

    # download files
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    cmd = f"rucio -v download --dir {download_dir} {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    downloaded_files = os.listdir(f"{download_dir.rstrip('/')}/{scope}")
    assert name in downloaded_files

    # add files
    did = did_factory.upload_test_file(mock_rse, scope=scope)
    name = did["name"]
    # download files
    cmd = f"rucio -v download --dir {download_dir.rstrip('/')}/second_test/ {scope}:{name}*"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    downloaded_files = os.listdir(f"{download_dir.rstrip('/')}/second_test/{scope}")
    assert name in downloaded_files

    tmp_dir.cleanup()


def test_download_pfn(did_factory, rucio_client, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio download files"""

    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    # download files
    temp_dir = TemporaryDirectory()
    download_dir = temp_dir.name
    replica_pfn = list(rucio_client.list_replicas([{"scope": scope, "name": name}]))[0]["rses"][mock_rse][0]
    cmd = f"rucio -v download --dir {download_dir} --rse {mock_rse} --pfn {replica_pfn} {mock_scope.external}:{name}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert re.search("Total files.*1", out) is not None

    # Try to use the --pfn without rse
    cmd = f"rucio -v download  --dir {download_dir.rstrip('/')}/duplicate --pfn {replica_pfn} {mock_scope.external}:{name}"
    exitcode, out, err = execute(cmd)

    assert "No RSE was given, selecting one." in err
    assert exitcode == 0
    assert re.search('Total files.*1', out) is not None

    # Download the pfn without an rse, except there is no RSE with that RSE
    non_existent_pfn = "http://fake.pfn.marker/"
    cmd = f"rucio -v download  --dir {download_dir.rstrip('/')}/duplicate --pfn {non_existent_pfn} {mock_scope.external}:{name}"
    exitcode, out, err = execute(cmd)

    assert "No RSE was given, selecting one." in err
    assert f"Could not find RSE for pfn {non_existent_pfn}" in err
    assert exitcode != 0


def test_download_file_with_impl(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Rucio download files with impl parameter assigned 'posix' value"""
    tmp_file1 = file_factory.file_generator()
    impl = "posix"
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} --impl {impl} {tmp_file1}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # download files

    download_dir = TemporaryDirectory()
    temp_dir = download_dir.name
    cmd = f"rucio -v download --dir {temp_dir} {mock_scope.external}:{tmp_file1.name} --impl {impl}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = f"ls {temp_dir.rstrip('/')}/{mock_scope.external}"  # search in /tmp/
    exitcode, out, _ = execute(cmd)
    assert re.search(tmp_file1.name, out) is not None

    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} --impl {impl} {tmp_file1}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # download files
    cmd = f"rucio -v download --dir {temp_dir} {mock_scope.external}:{tmp_file1.name}* --impl {impl}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = f"ls {temp_dir.rstrip('/')}/{mock_scope.external}"
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert re.search(tmp_file1.name, out) is not None


@pytest.mark.noparallel(reason="fails when run in parallel")
@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_download_no_subdir(did_factory, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download files with --no-subdir and check that files already found locally are not replaced"""

    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]
    download_dir = TemporaryDirectory()
    temp_dir = download_dir.name

    # download files with --no-subdir
    cmd = f"rucio -v download --no-subdir --dir {temp_dir} {scope}:{name}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    assert name in os.listdir(temp_dir)

    # download again with --no-subdir
    cmd = f"rucio -v download --no-subdir --dir {temp_dir} {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(r"Downloaded files:\s+0", out) is not None
    assert re.search(r"Files already found locally:\s+1", out) is not None

    download_dir.cleanup()


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_download_filter(did_factory, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download with filter options"""
    # Use filter option to download file with wildcarded name
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse, return_full_item=True)
    scope, name, uuid = did["did_scope"], did["did_name"], did["guid"]

    temp_dir = TemporaryDirectory()
    download_dir = temp_dir.name
    # Expected to fail
    wrong_guid = generate_uuid()
    cmd = f"rucio -v download --dir {download_dir} {scope}:* --filter guid={wrong_guid}"
    exitcode, _, _ = execute(cmd)
    assert exitcode != 0
    assert scope not in os.listdir(download_dir)  # Download dir wasn't created yet

    # Correct guuid
    cmd = f"rucio -v download --dir {download_dir} {scope}:* --filter guid={uuid}"
    execute(cmd)
    assert name in os.listdir(f"{download_dir.rstrip('/')}/{scope}")

    # Test without specifying the wildcarded did
    # Make a new did
    did = did_factory.upload_test_file(mock_rse, return_full_item=True)
    scope, name, uuid = did["did_scope"], did["did_name"], did["guid"]

    # Expected to fail
    wrong_guid = generate_uuid()
    cmd = f"rucio -v download --dir {download_dir} --scope {scope} --filter guid={wrong_guid}"
    exitcode, _, _ = execute(cmd)
    assert exitcode != 0
    assert name not in os.listdir(f"{download_dir.rstrip('/')}/{scope}")

    # Using the correct guuid
    cmd = f"rucio -v download --dir {download_dir} --scope {scope} --filter guid={uuid}"
    execute(cmd)
    assert name in os.listdir(f"{download_dir.rstrip('/')}/{scope}")

    # Only use filter option to download dataset
    dataset = did_factory.upload_test_dataset(mock_rse)
    scope, dataset_name, did_name = dataset[0]["dataset_scope"], dataset[0]["dataset_name"], dataset[1]["did_name"]

    cmd = f"rucio download --dir {download_dir} --scope {scope} --filter created_before=1900-01-01T00:00:00.000Z"
    execute(cmd)
    # Didn't create the dataset dir yet, nothing has been downloaded to it
    assert not os.path.exists(f"{download_dir.rstrip('/')}/{dataset_name}")

    cmd = f"rucio download --dir {download_dir} --scope {scope} --filter created_after=1900-01-01T00:00:00.000Z"
    execute(cmd)
    # TODO: https://github.com/rucio/rucio/issues/2926 !
    # assert did_name in os.listdir(f"{download_dir.rstrip('/')}/{dataset_name}")

    # Use filter option to download dataset with wildcarded name
    dataset = did_factory.upload_test_dataset(mock_rse)
    scope, dataset_name, did_name = dataset[0]["dataset_scope"], dataset[0]["dataset_name"], dataset[1]["did_name"]

    cmd = f"rucio download --dir {download_dir} {scope}:{dataset_name}* --filter created_before=1900-01-01T00:00:00.000Z"
    execute(cmd)
    # dataset will not yet exist
    assert not os.path.exists(f"{download_dir.rstrip('/')}/{dataset_name}")

    cmd = f"rucio download --dir {download_dir} {scope}:{dataset_name}* --filter created_after=1900-01-01T00:00:00.000Z"
    execute(cmd)
    assert did_name in os.listdir(f"{download_dir.rstrip('/')}/{dataset_name}")

    temp_dir.cleanup()


def test_download_timeout_options_accepted(did_factory, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download timeout options"""

    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)

    did = did_factory.upload_test_file(rse_name=mock_rse)
    scope = did["scope"]
    tmp_file1 = did["name"]

    # download files
    cmd = f"rucio download --dir /tmp --transfer-timeout 3 --transfer-speed-timeout 1000 {scope}:{tmp_file1}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "successfully downloaded" in err

    # Check that PFN the transfer-speed-timeout option is not accepted for --pfn
    cmd = f"rucio -v download --rse {mock_rse} --transfer-speed-timeout 1 --pfn http://a.b.c/ {scope}:{tmp_file1}"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "Download with --pfn doesn't support --transfer-speed-timeout" in err


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_download_metalink_file(did_factory, rucio_client, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download with metalink file"""
    metalink_file_path = generate_uuid()

    # Use filter and metalink option
    cmd = "rucio download --scope mock --filter size=1 --metalink=test"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "Arguments filter and metalink cannot be used together" in err

    # Use did and metalink option
    cmd = "rucio download --metalink=test mock:test"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "Arguments dids and metalink cannot be used together" in err

    # Download only with metalink file
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(rse_name=mock_rse)
    scope = did["scope"].external
    tmp_file_name = did["name"]
    replica_file = rucio_client.list_replicas([{"scope": scope, "name": tmp_file_name}], metalink=True)
    with open(metalink_file_path, "w+") as metalink_file:
        metalink_file.write(replica_file)
    cmd = f"rucio download --dir /tmp --metalink {metalink_file_path}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"{tmp_file_name} successfully downloaded" in err
    assert re.search("Total files.*1", out) is not None
    remove(metalink_file_path)
    cmd = f"ls /tmp/{scope}"
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_file_name, out) is not None


def test_download_succeeds_md5only(file_factory, rucio_client, client_rse_factory, rse_client, rse_name_generator, vo, mock_scope):
    """CLIENT(USER): Rucio download succeeds MD5 only"""
    # user has a file to upload
    filename = file_factory.file_generator()
    file_md5 = md5(filename)
    filesize = stat(filename).st_size
    lfn = {
        "name": filename.name,
        "scope": mock_scope.external,
        "bytes": filesize,
        "md5": file_md5,
    }
    # user uploads file
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_replicas(files=[lfn], rse=mock_rse)
    rse_settings = rsemgr.get_rse_info(rse=mock_rse, vo=vo)
    protocol = rsemgr.create_protocol(rse_settings, "write")
    protocol.connect()
    pfn = list(protocol.lfns2pfns(lfn).values())[0]
    protocol.put(filename.name, pfn, str(filename.parent))
    protocol.close()
    remove(filename)
    # download files
    cmd = f"rucio -v download --dir /tmp {mock_scope.external}:{filename.name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    # search for the files with ls
    cmd = f"ls /tmp/{mock_scope.external}"  # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(filename.name, out) is not None


def test_download_fails_badmd5(file_factory, rucio_client, client_rse_factory, rse_client, rse_name_generator, mock_scope, vo):
    """CLIENT(USER): Rucio download fails on MD5 mismatch"""
    # user has a file to upload
    filename = file_factory.file_generator()
    file_md5 = md5(filename)
    filesize = stat(filename).st_size
    lfn = {
        "name": filename.name,
        "scope": mock_scope.external,
        "bytes": filesize,
        "md5": "0123456789abcdef0123456789abcdef",
    }
    # user uploads file
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_replicas(files=[lfn], rse=mock_rse)
    rse_settings = rsemgr.get_rse_info(rse=mock_rse, vo=vo)
    protocol = rsemgr.create_protocol(rse_settings, "write")
    protocol.connect()
    pfn = list(protocol.lfns2pfns(lfn).values())[0]
    protocol.put(filename.name, pfn, str(filename.parent))
    protocol.close()
    remove(filename)

    # download file
    cmd = f"rucio -v download --dir /tmp {mock_scope.external}:{filename.name}"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0

    report = r"Local\ checksum\:\ {0},\ Rucio\ checksum\:\ 0123456789abcdef0123456789abcdef".format(file_md5)
    assert re.search(report, err) is not None

    # The file should not exist
    cmd = "ls /tmp/"  # search in /tmp/
    exitcode, out, err = execute(cmd)
    assert re.search(filename.name, out) is None


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_download_dataset(client_rse_factory, did_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download dataset"""

    tmp = TemporaryDirectory()
    download_dir = tmp.name
    # create dataset

    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    dataset = did_factory.upload_test_dataset(rse_name=mock_rse)
    scope, dataset_name, file = dataset[0]["dataset_scope"], dataset[0]["dataset_name"], dataset[1]["did_name"]

    # download dataset
    cmd = f"rucio -v download --dir {download_dir} {scope}:{dataset_name}"
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    search = f"{file} successfully downloaded"
    assert re.search(search, err) is not None

    tmp.cleanup()


def test_download_file_check_by_size(did_factory, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio download files"""

    tmp = TemporaryDirectory()
    download_dir = tmp.name

    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"], did["name"]

    cmd = f"rucio -v download --dir {download_dir} {scope}:{name}"
    execute(cmd)
    assert name in os.listdir(f'{download_dir.rstrip("/")}/{scope}')
    cmd = f'echo "dummy" >> {download_dir.rstrip("/")}/{scope}/{name}'
    execute(cmd)

    # Download file again and check for mismatch
    cmd = f"rucio -v download --check-local-with-filesize-only --dir {download_dir} {scope}:{name}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "File with same name exists locally, but filesize mismatches" in err


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_list_blocklisted_replicas(client_rse_factory, rse_client, rse_name_generator, did_factory):
    """CLIENT(USER): Rucio list replicas"""
    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = (
        "rucio-admin rse add-protocol --hostname blocklistreplica --scheme file --prefix /rucio --port 0 --impl rucio.rse.protocols.posix.Default "
        '--domain-json \'{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}}\' %s' % tmp_rse
    )

    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add files
    dataset = did_factory.upload_test_dataset(rse_name=tmp_rse)
    scope, dataset_name = dataset[0]["dataset_scope"], dataset[0]["dataset_name"]

    # Listing the replica should work before blocklisting the RSE
    cmd = f"rucio list-file-replicas {scope}:{dataset_name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert tmp_rse in out

    # Blocklist the rse
    cmd = f"rucio-admin rse update --rse {tmp_rse} --setting availability_read --value False"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert not err

    # list-file-replicas should, by default, list replicas from blocklisted rses
    cmd = f"rucio list-file-replicas {scope}:{dataset_name}"

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert tmp_rse in out


def test_create_rule(rse_name_generator, client_rse_factory, rse_client, rucio_client, did_factory):
    """CLIENT(USER): Rucio add rule"""

    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    # add rse
    tmp_rse = rse_name_generator()
    cmd = f"rucio-admin rse add {tmp_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add quota
    rucio_client.set_local_account_limit("root", tmp_rse, -1)
    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value ATLASSCRATCHDISK"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    # add quota
    rucio_client.set_local_account_limit("root", tmp_rse, -1)
    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value ATLASSCRATCHDISK"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    # add quota
    rucio_client.set_local_account_limit("root", tmp_rse, -1)
    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value ATLASSCRATCHDISK"
    exitcode, out, err = execute(cmd)

    # add rules
    cmd = f"rucio add-rule {scope}:{name} 3 'spacetoken=ATLASSCRATCHDISK'"

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    rule = out[:-1]  # trimming new line character
    assert re.match(r"^\w+$", rule)

    # check if rule exist for the file
    cmd = f"rucio list-rules {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(rule, out) is not None


def test_create_rule_delayed(client_rse_factory, rse_client, rse_name_generator, rucio_client, did_factory):
    """CLIENT(USER): Rucio add rule delayed"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)

    # add quota
    rucio_client.set_local_account_limit("root", tmp_rse, -1)

    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value ATLASRULEDELAYED"
    exitcode, out, err = execute(cmd)

    # try adding rule with an incorrect delay-injection. Must fail
    cmd = f"rucio add-rule --delay-injection asdsaf {scope}:{name} 1 'spacetoken=ATLASRULEDELAYED'"
    exitcode, out, err = execute(cmd)
    assert err
    assert exitcode != 0
    cmd = f"rucio add-rule --delay-injection 3600 {scope}:{name} 1 'spacetoken=ATLASRULEDELAYED'"

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert not err
    rule = out[:-1]  # trimming new line character
    cmd = f"rucio rule-info {rule}"

    exitcode, out, err = execute(cmd)
    out_lines = out.splitlines()
    assert any(re.match(r"State:.* INJECT", line) for line in out_lines)
    assert any(re.match(r"Locks OK/REPLICATING/STUCK:.* 0/0/0", line) for line in out_lines)
    # Check that "Created at" is approximately 3600 seconds in the future
    [created_at_line] = filter(lambda x: "Created at" in x, out_lines)
    created_at = re.search(r"Created at:\s+(\d.*\d)$", created_at_line).group(1)  # type: ignore
    created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert datetime.now(timezone.utc) + timedelta(seconds=3550) < created_at < datetime.now(timezone.utc) + timedelta(seconds=3650)


def test_delete_rule(did_factory, client_rse_factory, rse_client, rse_name_generator, rucio_client):
    """CLIENT(USER): rule deletion"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.set_local_account_limit("root", tmp_rse, -1)

    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value ATLASDELETERULE"
    execute(cmd)

    # add rules
    cmd = f"rucio add-rule {scope}:{name} 1 'spacetoken=ATLASDELETERULE'"
    execute(cmd)

    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(scope, name)
    exitcode, out, err = execute(cmd)

    (rule1, rule2) = out.split()
    # delete the rules for the file
    cmd = f"rucio delete-rule {rule1}"
    execute(cmd)

    cmd = f"rucio delete-rule {rule2}"
    execute(cmd)

    # search for the file
    cmd = f"rucio list-dids --filter type==all {scope}:{name}"
    _, out, _ = execute(cmd)
    assert 5 == len(out.splitlines())


def test_move_rule(did_factory, client_rse_factory, rse_client, rse_name_generator, rucio_client):
    """CLIENT(USER): Rucio move rule"""
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    # add rses
    tmp_rse1, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_rse_attribute(tmp_rse1, key="spacetoken", value="ATLASSCRATCHDISK")
    rucio_client.set_local_account_limit("root", tmp_rse1, -1)

    tmp_rse2, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_rse_attribute(tmp_rse2, key="spacetoken", value="ATLASSCRATCHDISK")
    rucio_client.set_local_account_limit("root", tmp_rse2, -1)

    tmp_rse3, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_rse_attribute(tmp_rse3, key="spacetoken", value="ATLASSCRATCHDISK")
    rucio_client.set_local_account_limit("root", tmp_rse3, -1)

    # add rules
    rule = rucio_client.add_replication_rule(dids=[{"scope": scope, "name": name}], copies=3, rse_expression=f"{tmp_rse1}|{tmp_rse2}|{tmp_rse3}", ignore_availability=True)[0]
    # move rule
    new_rule_expr = "'spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD'"
    cmd = f"rucio move-rule {rule} {new_rule_expr}"

    exitcode, out, err = execute(cmd)
    assert not err
    new_rule = out[:-1]  # trimming new line character

    # check if rule exist for the file
    cmd = f"rucio list-rules {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert re.search(new_rule, out) is not None


def test_move_rule_with_arguments(did_factory, client_rse_factory, rse_client, rse_name_generator, rucio_client):
    """CLIENT(USER): Rucio move rule"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    did = did_factory.upload_test_file(mock_rse)
    scope, name = did["scope"].external, did["name"]

    # add rses
    tmp_rse1, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_rse_attribute(tmp_rse1, key="spacetoken", value="ATLASSCRATCHDISK")
    rucio_client.set_local_account_limit("root", tmp_rse1, -1)

    tmp_rse2, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_rse_attribute(tmp_rse2, key="spacetoken", value="ATLASSCRATCHDISK")
    rucio_client.set_local_account_limit("root", tmp_rse2, -1)

    tmp_rse3, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.add_rse_attribute(tmp_rse3, key="spacetoken", value="ATLASSCRATCHDISK")
    rucio_client.set_local_account_limit("root", tmp_rse3, -1)

    # add rules
    rule = rucio_client.add_replication_rule(dids=[{"scope": scope, "name": name}], copies=3, rse_expression=f"{tmp_rse1}|{tmp_rse2}|{tmp_rse3}", ignore_availability=True)[0]  # Rule ID

    # move rule
    new_rule_expr = "spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD"
    new_rule_activity = "No User Subscription"
    new_rule_source_replica_expression = "spacetoken=ATLASSCRATCHDISK|spacetoken=ATLASSD"

    cmd = f"rucio move-rule --activity '{new_rule_activity}' --source-replica-expression '{new_rule_source_replica_expression}' {rule} '{new_rule_expr}'"

    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    new_rule_id = out[:-1]  # trimming new line character

    # check if rule exist for the file
    cmd = f"rucio list-rules {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert re.search(new_rule_id, out) is not None

    # check updated rule information
    cmd = f"rucio rule-info {new_rule_id}"
    exitcode, out, err = execute(cmd)
    assert new_rule_activity in out
    assert new_rule_source_replica_expression in out


def test_add_file_twice(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Add file twice"""
    tmp_file1 = file_factory.file_generator()
    # add file twice
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"

    exitcode, out, err = execute(cmd)
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"

    exitcode, out, err = execute(cmd)
    assert (
        re.search(
            f"File {mock_scope.external}:{tmp_file1.name} successfully uploaded on the storage",
            out,
        )
        is None
    )


def test_add_delete_add_file(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Add/Delete/Add"""
    tmp_file1 = file_factory.file_generator()
    # add file
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"

    exitcode, out, err = execute(cmd)

    # get the rule for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)

    rule = out
    # delete the file from the catalog
    cmd = f"rucio delete-rule {rule}"

    exitcode, out, err = execute(cmd)

    # delete the physical file
    cmd = f"find /tmp/rucio_rse/ -name {tmp_file1.name} |xargs rm"

    exitcode, out, err = execute(cmd)

    # modify the file to avoid same checksum
    cmd = f"echo 'delta' >> {tmp_file1}"

    exitcode, out, err = execute(cmd)

    # add the same file
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"

    exitcode, out, err = execute(cmd)

    assert (
        re.search(
            f"File {mock_scope.external}:{tmp_file1.name} successfully uploaded on the storage",
            out,
        )
        is None
    )


def test_attach_files_dataset(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope):
    """CLIENT(USER): Rucio attach files to dataset"""
    # Attach files to a dataset using the attach method
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()
    tmp_file3 = file_factory.file_generator()
    scope_name = mock_scope.external
    tmp_dsn = mock_scope.external + ":DSet" + rse_name_generator()  # something like mock:DSetMOCK_S0M37HING
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    # Adding files to a new dataset
    cmd = f"rucio upload --rse {mock_rse} --scope {scope_name} {tmp_file1} {tmp_dsn}"

    exitcode, out, err = execute(cmd)
    # upload the files
    cmd = f"rucio upload --rse {mock_rse} --scope {scope_name} {tmp_file2} {tmp_file3}"

    exitcode, out, err = execute(cmd)
    remove(tmp_file1)
    remove(tmp_file2)
    remove(tmp_file3)
    # attach the files to the dataset
    cmd = f"rucio attach {tmp_dsn} {scope_name}:{tmp_file2.name} {scope_name}:{tmp_file3.name}"
    exitcode, out, err = execute(cmd)
    # searching for the file in the new dataset
    cmd = f"rucio list-files {tmp_dsn}"

    exitcode, out, err = execute(cmd)
    # tmp_file2 must be in the dataset
    assert re.search(f"{mock_scope.external}:{tmp_file2.name}", out) is not None
    # tmp_file3 must be in the dataset
    assert re.search(f"{mock_scope.external}:{tmp_file3.name}", out) is not None


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_detach_files_dataset(did_factory, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(USER): Rucio detach files to dataset"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    dids = did_factory.upload_test_dataset(mock_rse, nb_files=3)
    scope, dataset_name = dids[0]["dataset_scope"], dids[0]["dataset_name"]
    tmp_file1, tmp_file2, tmp_file3 = dids[0]["did_name"], dids[1]["did_name"], dids[2]["did_name"]

    # detach the files to the dataset
    cmd = f"rucio detach {scope}:{dataset_name} {scope}:{tmp_file2} {scope}:{tmp_file3}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # searching for the file in the new dataset
    cmd = f"rucio list-files {scope}:{dataset_name}"
    exitcode, out, err = execute(cmd)

    # tmp_file1 must be in the dataset
    assert re.search(f"{scope}:{tmp_file1}", out) is not None
    # tmp_file3 must be removed (It was detached)
    assert re.search(f"{scope}:{tmp_file3}", out) is None


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_attach_file_twice(client_rse_factory, rse_client, rse_name_generator, did_factory):
    """CLIENT(USER): Rucio attach a file twice"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    # Test dataset has the files pre-attached
    dids = did_factory.upload_test_dataset(mock_rse, nb_files=1)[0]
    scope, dataset_name, tmp_file1 = dids["dataset_scope"], dids["dataset_name"], dids["did_name"]

    # attach the files to the dataset
    cmd = f"rucio attach {scope}:{dataset_name} {scope}:{tmp_file1}"

    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert re.search("The file already exists", err) is not None


def test_attach_dataset_twice(did_client, mock_scope):
    """CLIENT(USER): Rucio attach a dataset twice"""
    container = f"container_{generate_uuid()}"
    dataset = f"dataset_{generate_uuid()}"
    scope_name = mock_scope.external
    did_client.add_container(scope=mock_scope.external, name=container)
    did_client.add_dataset(scope=mock_scope.external, name=dataset)

    # Attach dataset to container
    cmd = f"rucio attach {scope_name}:{container} {scope_name}:{dataset}"
    exitcode, out, err = execute(cmd)

    # Attach again
    cmd = f"rucio attach {scope_name}:{container} {scope_name}:{dataset}"

    exitcode, out, err = execute(cmd)
    assert re.search("Data identifier already added to the destination content", err) is not None


@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="Requires DB session to create datasets",
)
def test_detach_non_existing_file(
    did_factory,
    client_rse_factory,
    rse_client,
    rse_name_generator
):
    """CLIENT(USER): Rucio detach a non existing file"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    dids = did_factory.upload_test_dataset(mock_rse)[0]
    scope, dataset_name = dids["dataset_scope"], dids["dataset_name"]

    # attach the files to the dataset
    cmd = f"rucio detach {scope}{dataset_name} {scope}:file_ghost"

    exitcode, out, err = execute(cmd)
    assert re.search("Data identifier not found.", err) is not None


@pytest.mark.dirty
def test_list_did_recursive():
    """CLIENT(USER): List did recursive"""
    # Setup nested collections
    tmp_scope = "mock"
    tmp_container_1 = f"container_{generate_uuid()}"
    cmd = f"rucio add-container {tmp_scope}:{tmp_container_1}"
    exitcode, out, err = execute(cmd)
    tmp_container_2 = f"container_{generate_uuid()}"
    cmd = f"rucio add-container {tmp_scope}:{tmp_container_2}"
    exitcode, out, err = execute(cmd)
    tmp_container_3 = f"container_{generate_uuid()}"
    cmd = f"rucio add-container {tmp_scope}:{tmp_container_3}"
    exitcode, out, err = execute(cmd)
    cmd = f"rucio attach {tmp_scope}:{tmp_container_1} {tmp_scope}:{tmp_container_2}"
    exitcode, out, err = execute(cmd)
    cmd = f"rucio attach {tmp_scope}:{tmp_container_2} {tmp_scope}:{tmp_container_3}"
    exitcode, out, err = execute(cmd)

    # All attached DIDs are expected
    cmd = f"rucio list-dids {tmp_scope}:{tmp_container_1} --recursive"
    exitcode, out, err = execute(cmd)
    assert re.search(tmp_container_1, out) is not None
    assert re.search(tmp_container_2, out) is not None
    assert re.search(tmp_container_3, out) is not None

    # Wildcards are not allowed to use with --recursive
    cmd = f"rucio list-dids {tmp_scope}:* --recursive"
    exitcode, out, err = execute(cmd)
    assert re.search("Option recursive cannot be used with wildcards", err) is not None


@pytest.mark.dirty
def test_attach_many_dids(rse_name_generator, mock_scope, did_client):
    """CLIENT(USER): Rucio attach many (>1000) DIDs"""
    # Setup data for CLI check
    tmp_dsn_name = "Container" + rse_name_generator()
    tmp_dsn_did = mock_scope.external + ":" + tmp_dsn_name
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name, did_type="CONTAINER")

    files = [
        {
            "name": f"dsn_{generate_uuid()}",
            "scope": mock_scope.external,
            "type": "DATASET",
        }
        for i in range(0, 1500)
    ]
    did_client.add_dids(files[:1000])
    did_client.add_dids(files[1000:])

    # Attaching over 1000 DIDs with CLI
    cmd = f"rucio attach {tmp_dsn_did}"
    for tmp_file in files:
        cmd += f" {tmp_file['scope']}:{tmp_file['name']}"
    exitcode, out, err = execute(cmd)

    # Checking if the execution was successful and if the DIDs belong together
    assert re.search("DIDs successfully attached", out) is not None
    cmd = f"rucio list-content {tmp_dsn_did}"

    exitcode, out, err = execute(cmd)
    # first dataset must be in the container
    assert re.search(f"{mock_scope.external}:{files[0]['name']}", out) is not None
    # last dataset must be in the container
    assert re.search(f"{mock_scope.external}:{files[-1]['name']}", out) is not None

    # Setup data with file
    did_file_path = "list_dids.txt"
    files = [
        {
            "name": f"dsn_{generate_uuid()}",
            "scope": mock_scope.external,
            "type": "DATASET",
        }
        for i in range(0, 1500)
    ]
    did_client.add_dids(files[:1000])
    did_client.add_dids(files[1000:])

    with open(did_file_path, "w") as did_file:
        for file in files:
            did_file.write(file["scope"] + ":" + file["name"] + "\n")
        did_file.close()

    # Attaching over 1000 files per file
    cmd = f"rucio attach {tmp_dsn_did} -f {did_file_path}"

    exitcode, out, err = execute(cmd)
    remove(did_file_path)

    # Checking if the execution was successful and if the DIDs belong together
    assert re.search("DIDs successfully attached", out) is not None
    cmd = f"rucio list-content {tmp_dsn_did}"

    exitcode, out, err = execute(cmd)
    # first file must be in the dataset
    assert re.search(f"{mock_scope.external}:{files[0]['name']}", out) is not None
    # last file must be in the dataset
    assert re.search(f"{mock_scope.external}:{files[-1]['name']}", out) is not None


@pytest.mark.dirty
def test_attach_many_dids_twice(mock_scope, did_client):
    """CLIENT(USER): Attach many (>1000) DIDs twice"""
    # Setup data for CLI check
    container_name = "container" + generate_uuid()
    container = mock_scope.external + ":" + container_name
    did_client.add_did(scope=mock_scope.external, name=container_name, did_type="CONTAINER")

    datasets = [
        {
            "name": f"dsn_{generate_uuid()}",
            "scope": mock_scope.external,
            "type": "DATASET",
        }
        for i in range(0, 1500)
    ]
    did_client.add_dids(datasets[:1000])
    did_client.add_dids(datasets[1000:])

    # Attaching over 1000 DIDs with CLI
    cmd = f"rucio attach {container}"
    for dataset in datasets:
        cmd += f" {dataset['scope']}:{dataset['name']}"
    exitcode, out, err = execute(cmd)

    # Attaching twice
    cmd = f"rucio attach {container}"
    for dataset in datasets:
        cmd += f" {dataset['scope']}:{dataset['name']}"
    exitcode, out, err = execute(cmd)
    assert re.search("DIDs successfully attached", out) is not None

    # Attaching twice plus one DID that is not already attached
    new_dataset = {
        "name": f"dsn_{generate_uuid()}",
        "scope": mock_scope.external,
        "type": "DATASET",
    }
    datasets.append(new_dataset)
    did_client.add_did(scope=mock_scope.external, name=new_dataset["name"], did_type="DATASET")
    cmd = f"rucio attach {container}"
    for dataset in datasets:
        cmd += f" {dataset['scope']}:{dataset['name']}"
    exitcode, out, err = execute(cmd)
    assert re.search("DIDs successfully attached", out) is not None
    cmd = f"rucio list-content {container}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{new_dataset['name']}", out) is not None


@pytest.mark.noparallel(reason="might override global RSE settings")
def test_import_data(rse_name_generator, rse_client):
    """CLIENT(ADMIN): Import data into rucio"""
    file_path = "data_import.json"
    rses = {rse["rse"]: rse for rse in rse_client.list_rses()}
    rses[rse_name_generator()] = {"country_name": "test"}
    data = {"rses": rses}
    with open(file_path, "w+") as file:
        file.write(render_json(**data))
    cmd = f"rucio-admin data import {file_path}"
    exitcode, out, err = execute(cmd)
    assert re.search("Data successfully imported", out) is not None
    remove(file_path)


@pytest.mark.noparallel(reason="fails when run in parallel")
def test_export_data():
    """CLIENT(ADMIN): Export data from rucio"""
    file_path = "data_export.json"
    cmd = f"rucio-admin data export {file_path}"
    exitcode, out, err = execute(cmd)
    assert re.search("Data successfully exported", out) is not None
    remove(file_path)


@pytest.mark.dirty
@pytest.mark.noparallel(reason="fails when run in parallel")
def test_set_tombstone(client_rse_factory, rse_client, rse_name_generator, rucio_client):
    """CLIENT(ADMIN): set a tombstone on a replica."""
    # Set tombstone on one replica
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rse = mock_rse
    scope = "mock"
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, "aaaaaaaa")
    cmd = f"rucio-admin replicas set-tombstone {scope}:{name} --rse {rse}"
    exitcode, out, err = execute(cmd)
    assert re.search("Set tombstone successfully", err) is not None

    # Set tombstone on locked replica
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, "aaaaaaaa")
    rucio_client.add_replication_rule([{"name": name, "scope": scope}], 1, rse, locked=True)
    cmd = f"rucio-admin replicas set-tombstone {scope}:{name} --rse {rse}"
    exitcode, out, err = execute(cmd)
    assert re.search("Replica is locked", err) is not None

    # Set tombstone on not found replica
    name = generate_uuid()
    cmd = f"rucio-admin replicas set-tombstone {scope}:{name} --rse {rse}"
    exitcode, out, err = execute(cmd)
    assert re.search("Replica not found", err) is not None


@pytest.mark.noparallel(reason="modifies account limit on pre-defined RSE")
def test_list_account_limits(rucio_client, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT (USER): list account limits."""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rse = mock_rse
    rse_exp = f"MOCK3|{rse}"
    account = "root"
    local_limit = 10
    global_limit = 20
    rucio_client.set_local_account_limit(account, rse, local_limit)
    rucio_client.set_global_account_limit(account, rse_exp, global_limit)
    cmd = f"rucio list-account-limits {account}"
    exitcode, out, err = execute(cmd)
    assert re.search(f".*{rse}.*{local_limit}.*", out) is not None
    assert re.search(f".*{rse_exp}.*{global_limit}.*", out) is not None
    cmd = f"rucio list-account-limits --rse {rse} {account}"
    exitcode, out, err = execute(cmd)
    assert re.search(f".*{rse}.*{local_limit}.*", out) is not None
    assert re.search(f".*{rse_exp}.*{global_limit}.*", out) is not None
    rucio_client.set_local_account_limit(account, rse, -1)
    rucio_client.set_global_account_limit(account, rse_exp, -1)


@pytest.mark.noparallel(reason="modifies account limit on pre-defined RSE")
@pytest.mark.skipif(
    "SUITE" in os.environ and os.environ["SUITE"] == "client",
    reason="uses abacus daemon and core functions",
)
def test_list_account_usage(rucio_client, rse_client, vo):
    """CLIENT (USER): list account usage."""
    from rucio.common.types import InternalAccount
    from rucio.core.account_counter import increase
    from rucio.daemons.abacus import account as abacus_account
    from rucio.db.sqla import models, session

    rse = "MOCK4"
    rse_id = rse_client.get_rse(rse=rse)['id']
    db_session = session.get_session()
    for model in [models.AccountUsage, models.AccountLimit, models.AccountGlobalLimit, models.UpdatedAccountCounter]:
        stmt = delete(model)
        db_session.execute(stmt)

    db_session.commit()

    rse_exp = f"MOCK|{rse}"
    account = "root"
    usage = 4
    local_limit = 10
    local_left = local_limit - usage
    global_limit = 20
    global_left = global_limit - usage

    rucio_client.set_local_account_limit(account, rse, local_limit)
    rucio_client.set_global_account_limit(account, rse_exp, global_limit)
    increase(rse_id, InternalAccount(account, vo=vo), 1, usage)

    abacus_account.run(once=True)

    cmd = f"rucio list-account-usage {account}"
    exitcode, out, err = execute(cmd)
    assert re.search(f".*{rse}.*{usage}.*{local_limit}.*{local_left}", out) is not None
    assert re.search(f".*MOCK|{rse}.*{usage}.*{global_limit}.*{global_left}", out) is not None

    cmd = f"rucio list-account-usage --rse {rse} {account}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert re.search(f".*{rse}.*{usage}.*{local_limit}.*{local_left}", out) is not None
    assert (
        re.search(
            f".*MOCK|{rse}.*{usage}.*{global_limit}.*{global_left}",
            out,
        )
        is not None
    )
    rucio_client.set_local_account_limit(account, rse, -1)
    rucio_client.set_global_account_limit(account, rse_exp, -1)


def test_get_set_delete_limits_rse(account_name_generator, client_rse_factory, rse_client, rse_name_generator):
    """CLIENT(ADMIN): Get, set and delete RSE limits"""
    name = generate_uuid()
    value = random.randint(0, 100000)
    name2 = generate_uuid()
    value2 = random.randint(0, 100000)
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    name3 = generate_uuid()
    value3 = account_name_generator()
    cmd = f"rucio-admin rse set-limit {mock_rse} {name} {value}"
    execute(cmd)
    cmd = f"rucio-admin rse set-limit {mock_rse} {name2} {value2}"
    execute(cmd)
    cmd = f"rucio-admin rse info {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{name}: {value}", out) is not None
    assert re.search(f"{name2}: {value2}", out) is not None
    new_value = random.randint(100001, 999999999)
    cmd = f"rucio-admin rse set-limit {mock_rse} {name} {new_value}"
    execute(cmd)
    cmd = f"rucio-admin rse info {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{name}: {new_value}", out) is not None
    assert re.search(f"{name}: {value}", out) is None
    assert re.search(f"{name2}: {value2}", out) is not None
    cmd = f"rucio-admin rse delete-limit {mock_rse} {name}"
    execute(cmd)
    cmd = f"rucio-admin rse info {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{name}: {new_value}", out) is None
    assert re.search(f"{name2}: {value2}", out) is not None
    cmd = f"rucio-admin rse delete-limit {mock_rse} {name}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"Limit {name} not defined in RSE {mock_rse}", err) is not None
    cmd = f"rucio-admin rse set-limit {mock_rse} {name3} {value3}"
    exitcode, out, err = execute(cmd)
    assert re.search("The RSE limit value must be an integer", err) is not None
    cmd = f"rucio-admin rse info {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{name3}: {value3}", out) is None
    assert re.search(f"{name2}: {value2}", out) is not None


def test_upload_recursive_ok(rse_name_generator, client_rse_factory, rse_client, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    folder = "folder_" + generate_uuid()
    folder1 = f"{folder}/folder_{generate_uuid()}"
    folder2 = f"{folder}/folder_{generate_uuid()}"
    folder3 = f"{folder}/folder_{generate_uuid()}"
    folder11 = f"{folder1}/folder_{generate_uuid()}"
    folder12 = f"{folder1}/folder_{generate_uuid()}"
    folder13 = f"{folder1}/folder_{generate_uuid()}"
    file1 = f"file_{generate_uuid()}"
    file2 = f"file_{generate_uuid()}"
    cmd = f"mkdir {folder}"
    execute(cmd)
    cmd = f"mkdir {folder1} && mkdir {folder2} && mkdir {folder3}"
    execute(cmd)
    cmd = f"mkdir {folder11} && mkdir {folder12} && mkdir {folder13}"
    execute(cmd)
    cmd = f'echo "{generate_uuid()}" > {folder11}/{file1}.txt'
    execute(cmd)
    cmd = f'echo "{generate_uuid()}" > {folder2}/{file2}.txt'
    execute(cmd)
    cmd = f"rucio upload --scope {mock_scope.external} --rse {mock_rse} --recursive {folder}/"
    execute(cmd)
    cmd = f"rucio list-content {mock_scope.external}:{folder}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{folder1.split('/')[-1]}", out) is not None
    assert re.search(f"{mock_scope.external}:{folder2.split('/')[-1]}", out) is not None
    assert re.search(f"{mock_scope.external}:{folder3.split('/')[-1]}", out) is None
    cmd = f"rucio list-content {mock_scope.external}:{folder1.split('/')[-1]}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{folder11.split('/')[-1]}", out) is not None
    assert re.search(f"{mock_scope.external}:{folder12.split('/')[-1]}", out) is None
    assert re.search(f"{mock_scope.external}:{folder13.split('/')[-1]}", out) is None
    cmd = f"rucio list-content {mock_scope.external}:{folder11.split('/')[-1]}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{file1}", out) is not None
    cmd = f"rucio list-content {mock_scope.external}:{folder2.split('/')[-1]}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{file2}", out) is not None
    cmd = f"rm -rf {folder}"
    execute(cmd)


def test_upload_recursive_subfolder(client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure in a subfolder"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    folder = "folder_" + generate_uuid()
    folder1 = f"{folder}/folder_{generate_uuid()}"
    folder11 = f"{folder1}/folder_{generate_uuid()}"
    file1 = f"file_{generate_uuid()}"
    cmd = f"mkdir {folder}"
    execute(cmd)
    cmd = f"mkdir {folder1}"
    execute(cmd)
    cmd = f"mkdir {folder11}"
    execute(cmd)
    cmd = f'echo "{generate_uuid()}" > {folder11}/{file1}.txt'
    execute(cmd)
    cmd = f"rucio upload --scope {mock_scope.external} --rse {mock_rse} --recursive {folder1}/"
    execute(cmd)
    cmd = f"rucio list-content {mock_scope.external}:{folder}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{folder1.split('/')[-1]}", out) is None
    cmd = f"rucio list-content {mock_scope.external}:{folder1.split('/')[-1]}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{folder11.split('/')[-1]}", out) is not None
    cmd = f"rucio list-content {mock_scope.external}:{folder11.split('/')[-1]}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{file1}", out) is not None
    cmd = f"rm -rf {folder}"
    execute(cmd)


def test_recursive_empty(client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure with an empty folder"""
    folder = "folder_" + generate_uuid()
    folder1 = f"{folder}/folder_{generate_uuid()}"
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    cmd = f"mkdir {folder}"
    execute(cmd)
    cmd = f"mkdir {folder1}"
    execute(cmd)
    cmd = f"rucio upload --scope {mock_scope.external} --rse {mock_rse} --recursive {folder}/"
    execute(cmd)
    cmd = f"rucio list-content {mock_scope.external}:{folder}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{folder1.split('/')[-1]}", out) is None
    cmd = f"rm -rf {folder}"
    execute(cmd)


def test_upload_recursive_only_files(client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): Upload and preserve folder structure only with files"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    folder = "folder_" + generate_uuid()
    file1 = f"file_{generate_uuid()}"
    file2 = f"file_{generate_uuid()}"
    file3 = f"file_{generate_uuid()}"
    cmd = f"mkdir {folder}"
    execute(cmd)
    cmd = f'echo "{generate_uuid()}" > {folder}/{file1}.txt'
    execute(cmd)
    cmd = f'echo "{generate_uuid()}" > {folder}/{file2}.txt'
    execute(cmd)
    cmd = f'echo "{generate_uuid()}" > {folder}/{file3}.txt'
    execute(cmd)
    cmd = f"rucio upload --scope {mock_scope.external} --rse {mock_rse} --recursive {folder}/"
    execute(cmd)
    cmd = f"rucio list-content {mock_scope.external}:{folder}"
    exitcode, out, err = execute(cmd)
    assert re.search(f"{mock_scope.external}:{file1}", out) is not None
    assert re.search(f"{mock_scope.external}:{file2}", out) is not None
    assert re.search(f"{mock_scope.external}:{file3}", out) is not None
    cmd = f"rucio ls {mock_scope.external}:{folder}"
    exitcode, out, err = execute(cmd)
    assert re.search("DATASET", out) is not None
    cmd = f"rm -rf {folder}"
    execute(cmd)


def test_deprecated_command_line_args():
    """CLIENT(USER): Warn about deprecated command line args"""
    cmd = "rucio get --trace_appid 0"

    exitcode, out, err = execute(cmd)
    assert "Warning: The commandline argument --trace_appid is deprecated! Please use --trace-appid in the future." in out


def test_rucio_admin_expiration_date_is_deprecated():
    """CLIENT(USER): Warn about deprecated command line args"""
    cmd = "rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --expiration-date 168 --reason 'test only'"

    exitcode, out, err = execute(cmd)
    assert "Warning: The commandline argument --expiration-date is deprecated! Please use --duration in the future." in out


def test_rucio_admin_expiration_date_not_defined():
    """CLIENT(USER): Warn about deprecated command line arg"""
    cmd = "rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --reason 'test only'"

    exitcode, out, err = execute(cmd)
    assert err != 0
    assert "the following arguments are required" in err


def test_rucio_admin_duration_out_of_bounds():
    """CLIENT(USER): Warn about deprecated command line arg"""
    cmd = "rucio-admin replicas declare-temporary-unavailable srm://se.bfg.uni-freiburg.de/pnfs/bfg.uni-freiburg.de/data/atlasdatadisk/rucio/user/jdoe/e2/a7/jdoe.TXT.txt --duration 622080000 --reason 'test only'"

    exitcode, out, err = execute(cmd)
    assert err != 0
    assert re.search(r"The given duration of 7199 days exceeds the maximum duration of 30 days.", err)


def test_update_rule_cancel_requests_args():
    """CLIENT(USER): update rule cancel requests must have a state defined"""
    cmd = "rucio update-rule --cancel-requests RULE"
    exitcode, out, err = execute(cmd)
    assert "--stuck or --suspend must be specified when running --cancel-requests" in err
    assert exitcode != 0


def test_update_rule_unset_child_rule(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope, rucio_client):
    """CLIENT(USER): update rule unsets a child rule property"""

    # PREPARING FILE AND RSE
    # add files
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_file = file_factory.file_generator()
    tmp_fname = tmp_file.name
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" not in err

    for i in range(2):
        tmp_rse = rse_name_generator()
        cmd = f"rucio-admin rse add {tmp_rse}"
        exitcode, out, err = execute(cmd)
        assert not err

        rucio_client.set_local_account_limit("root", tmp_rse, -1)
        cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value RULELOC{i}"
        exitcode, out, err = execute(cmd)
        assert not err

    # PREPARING THE RULES
    # add rule
    rule_expr = "spacetoken=RULELOC0"
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_fname} 1 '{rule_expr}'"
    exitcode, out, err = execute(cmd)
    assert not err
    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file.name)
    exitcode, out, err = execute(cmd)
    parentrule_id, _ = out.split()

    # LINKING THE RULES (PARENT/CHILD)
    # move rule
    new_rule_expr = rule_expr + "|spacetoken=RULELOC1"
    cmd = f"rucio move-rule {parentrule_id} '{new_rule_expr}'"
    exitcode, out, err = execute(cmd)
    childrule_id = out.strip()
    assert err == ""

    # check if new rule exists for the file
    cmd = f"rucio list-rules {mock_scope.external}:{tmp_fname}"
    exitcode, out, err = execute(cmd)
    assert re.search(childrule_id, out) is not None

    # DETACHING THE RULES
    # child-rule-id None means to unset the variable on the parent rule
    cmd = f"rucio update-rule --child-rule-id None {parentrule_id}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" not in err
    assert re.search("Updated Rule", out) is not None

    cmd = f"rucio update-rule --child-rule-id None {parentrule_id}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" in err
    assert re.search("Cannot detach child when no such relationship exists", err) is not None


def test_update_rule_no_child_selfassign(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope, rucio_client):
    """CLIENT(USER): do not permit to assign self as own child"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_file = file_factory.file_generator()
    tmp_fname = tmp_file.name
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" not in err

    tmp_rse = rse_name_generator()
    cmd = f"rucio-admin rse add {tmp_rse}"
    exitcode, out, err = execute(cmd)
    assert not err

    rucio_client.set_local_account_limit("root", tmp_rse, -1)

    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value RULELOC"
    exitcode, out, err = execute(cmd)
    assert not err

    # PREPARING THE RULES
    # add rule
    rule_expr = "spacetoken=RULELOC"
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_fname} 1 '{rule_expr}'"
    exitcode, out, err = execute(cmd)
    assert not err

    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file.name)
    exitcode, out, err = execute(cmd)
    parentrule_id, _ = out.split()

    # now for the test
    # TODO: merge this with the other update_rule test from issue #5930
    cmd = f"rucio update-rule --child-rule-id {parentrule_id} {parentrule_id}"
    exitcode, out, err = execute(cmd)
    # TODO: add a more specific assertion here.
    assert err


def test_update_rule_boost_rule_arg(file_factory, rucio_client, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): update a rule with the `--boost_rule` option"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.set_local_account_limit("root", mock_rse, -1)
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"

    exitcode, out, err = execute(cmd)

    # add rse
    tmp_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.set_local_account_limit("root", tmp_rse, -1)

    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value ATLASDELETERULE"

    exitcode, out, err = execute(cmd)

    # add rules
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_file1.name} 1 'spacetoken=ATLASDELETERULE'"

    exitcode, out, err = execute(cmd)

    # get the rules for the file
    cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(mock_scope.external, tmp_file1.name)

    exitcode, out, err = execute(cmd)
    (rule1, rule2) = out.split()

    # update the rules
    cmd = f"rucio update-rule --boost-rule {rule1}"

    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    cmd = f"rucio update-rule --boost-rule {rule2}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0


def test_rucio_list_file_replicas(file_factory, rse_name_generator, client_rse_factory, rse_client, mock_scope, rucio_client):
    """CLIENT(USER): List missing file replicas"""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    rucio_client.set_local_account_limit("root", mock_rse, -1)
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"
    exitcode, out, err = execute(cmd)

    # add rse
    tmp_rse = rse_name_generator()
    cmd = f"rucio-admin rse add {tmp_rse}"

    exitcode, out, err = execute(cmd)
    rucio_client.set_local_account_limit("root", tmp_rse, -1)

    # add rse attributes
    cmd = f"rucio-admin rse set-attribute --rse {tmp_rse} --key spacetoken --value MARIOSPACEODYSSEY"

    exitcode, out, err = execute(cmd)

    # add rules
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_file1.name} 1 'spacetoken=MARIOSPACEODYSSEY'"

    exitcode, out, err = execute(cmd)
    cmd = f'rucio list-file-replicas {mock_scope.external}:{tmp_file1.name} --rses "spacetoken=MARIOSPACEODYSSEY" --missing'

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert tmp_file1.name in out


def test_rucio_create_rule_with_0_copies(file_factory, client_rse_factory, rse_client, rse_name_generator, mock_scope):
    """CLIENT(USER): The creation of a rule with 0 copies shouldn't be possible."""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    tmp_file1 = file_factory.file_generator()
    # add files
    cmd = f"rucio upload --rse {mock_rse} --scope {mock_scope.external} {tmp_file1}"

    exitcode, out, err = execute(cmd)
    # Try to add a rules with 0 copies, this shouldn't be possible
    cmd = f"rucio add-rule {mock_scope.external}:{tmp_file1.name} 0 MOCK"

    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "The number of copies for a replication rule should be greater than 0." in err


def test_add_lifetime_exception(did_client, mock_scope):
    """CLIENT(USER): Rucio submission of lifetime exception"""
    container = f"container_{generate_uuid()}"
    dataset = f"dataset_{generate_uuid()}"
    did_client.add_container(scope=mock_scope.external, name=container)
    did_client.add_dataset(scope=mock_scope.external, name=dataset)
    file = NamedTemporaryFile(suffix="lifetime_exception.txt")
    filename = file.name
    with open(filename, "w") as file_:
        file_.write(f"{mock_scope.external}:{dataset}\n")

    # Try adding an exception
    cmd = f'rucio add-lifetime-exception --inputfile {filename} --reason "Needed for analysis" --expiration 2015-10-30'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "Nothing to submit" in err

    with open(filename, "w") as file_:
        file_.write(f"{mock_scope.external}:{dataset}\n")
        file_.write(f"{mock_scope.external}:{container}")

    # Try adding an exception
    cmd = f'rucio add-lifetime-exception --inputfile {filename} --reason "Needed for analysis" --expiration 2015-10-30'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "One or more DIDs are containers. They will be resolved into a list of datasets" in err


def test_add_lifetime_exception_large_dids_number(mock_scope):
    """CLIENT(USER): Check that exceptions with more than 1k DIDs are supported"""
    file = NamedTemporaryFile(suffix="lifetime_exception_many_dids.txt")
    filename = file.name
    with open(filename, "w") as file_:
        for _ in range(2000):
            file_.write(f"{mock_scope.external}:{generate_uuid()}\n")

    # Try adding an exception
    cmd = f'rucio add-lifetime-exception --inputfile {filename} --reason "Needed for analysis" --expiration 2015-10-30'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "Nothing to submit" in err


def test_admin_rse_update_unsupported_option(client_rse_factory, rse_client, rse_name_generator):
    """ADMIN CLIENT: Rse update should throw an unsupported option exception on an unsupported exception."""
    mock_rse, _ = client_rse_factory.make_posix_rse(rse_client, rse_name_generator)
    exitcode, out, err = execute(f"rucio-admin rse update --setting test_with_non_existing_option --value 3 --rse {mock_rse}")

    assert exitcode != 0
    assert "Details: The key 'test_with_non_existing_option' does not exist for RSE properties.\n" in err

    exitcode, out, err = execute(f"rucio-admin rse update --setting country_name --value France --rse {mock_rse}")
    assert exitcode == 0
    assert not err


@pytest.mark.parametrize(
    "file_config_mock",
    [
        {
            "overrides": [
                (
                    "lifetime_model",
                    "cutoff_date",
                    (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d"),
                )
            ]
        }
    ],
    indirect=True,
)
def test_lifetime_cli(did_client, rse_name_generator, mock_scope, file_config_mock):
    """CLIENT(USER): Check CLI to declare lifetime exceptions"""
    # Setup data for CLI check
    tmp_dsn_name = "container" + rse_name_generator()
    tmp_dsn_did = mock_scope.external + ":" + tmp_dsn_name
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name, did_type="DATASET")
    did_client.set_metadata(
        scope=mock_scope.external,
        name=tmp_dsn_name,
        key="eol_at",
        value=(datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d"),
    )
    with NamedTemporaryFile(mode="w+") as fp:
        fp.write(f"{tmp_dsn_did}\n" * 2)
        fp.seek(0)
        exitcode, out, err = execute(f"rucio add-lifetime-exception --inputfile {fp.name} --reason 'For testing purpose; please ignore.' --expiration 2124-01-01")
        assert "does not exist" not in err


@pytest.mark.parametrize(
    "file_config_mock",
    [
        {
            "overrides": [
                (
                    "lifetime_model",
                    "cutoff_date",
                    (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d"),
                )
            ]
        }
    ],
    indirect=True,
)
def test_lifetime_container_resolution(did_client, rse_name_generator, mock_scope, file_config_mock):
    """CLIENT(USER): Check that the CLI to declare lifetime exceptions resolve contaiers"""
    # Setup data for CLI check
    tmp_dsn_name1 = "dataset" + rse_name_generator()
    tmp_dsn_name2 = "dataset" + rse_name_generator()
    tmp_cnt_name = "container" + rse_name_generator()
    tmp_cnt_did = mock_scope.external + ":" + tmp_cnt_name
    # Create 2 datasets and 1 container and attach dataset to container
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name1, did_type="DATASET")
    did_client.add_did(scope=mock_scope.external, name=tmp_dsn_name2, did_type="DATASET")
    did_client.add_did(scope=mock_scope.external, name=tmp_cnt_name, did_type="CONTAINER")
    did_client.attach_dids(
        scope=mock_scope.external,
        name=tmp_cnt_name,
        dids=[
            {"scope": mock_scope.external, "name": tmp_dsn_name1},
            {"scope": mock_scope.external, "name": tmp_dsn_name2},
        ],
    )
    # Set eol_at for the first dataset but not to the second one
    did_client.set_metadata(
        scope=mock_scope.external,
        name=tmp_dsn_name1,
        key="eol_at",
        value=(datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d"),
    )

    with NamedTemporaryFile(mode="w+") as fp:
        fp.write(f"{tmp_cnt_did}")
        fp.seek(0)
        exitcode, out, err = execute(f"rucio add-lifetime-exception --inputfile {fp.name} --reason 'For testing purpose; please ignore.' --expiration 2124-01-01")
        assert f"{mock_scope.external}:{tmp_dsn_name2} is not affected by the lifetime model"
        assert f"{mock_scope.external}:{tmp_dsn_name1} will be declared"
