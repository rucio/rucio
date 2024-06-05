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
import tempfile
from os import environ, listdir, path, remove

from rucio.common.utils import generate_uuid, md5
from rucio.tests.common import execute, file_generator, rse_name_generator, scope_name_generator

rcom = "bin/rcom"


def test_upload_file(rucio_client, rse_factory, mock_scope):
    """CLIENT(USER): Rucio upload files"""
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    file2 = file_generator()
    file3 = file_generator()
    command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external} --files {file1} {file2} {file3}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    uploaded_replicas = rucio_client.list_replicas(dids=[{"name": path.basename(file), "scope": mock_scope.external} for file in [file1, file2, file3]])
    assert len([i for i in uploaded_replicas]) == 3


def test_upload_file_register_after_upload(rse_factory, mock_scope, vo, rucio_client):
    """CLIENT(USER): Rucio upload files with registration after upload"""
    # normal upload
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    file2 = file_generator()
    file3 = file_generator()
    file1_name = path.basename(file1)
    command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external} --files {file1} {file2} {file3} --register-after-upload"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    remove(file1)
    remove(file2)
    remove(file3)

    # removing replica -> file on RSE should be overwritten
    # (simulating an upload error, where a part of the file is uploaded but the replica is not registered)
    if "SUITE" not in environ or environ["SUITE"] != "client":
        from rucio.db.sqla import models, session

        db_session = session.get_session()
        db_session.query(models.RSEFileAssociation).filter_by(name=file1_name, scope=mock_scope).delete()
        db_session.query(models.ReplicaLock).filter_by(name=file1_name, scope=mock_scope).delete()
        db_session.query(models.ReplicationRule).filter_by(name=file1_name, scope=mock_scope).delete()
        db_session.query(models.DidMeta).filter_by(name=file1_name, scope=mock_scope).delete()
        db_session.query(models.DataIdentifier).filter_by(name=file1_name, scope=mock_scope).delete()
        db_session.commit()

        file4 = file_generator()
        checksum_file4 = md5(file4)
        command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external} --name {file1_name} --file {file4} --register-after-upload"
        exitcode, _, _ = execute(command)
        assert exitcode == 0
        assert checksum_file4 == [replica for replica in rucio_client.list_replicas(dids=[{"name": file1_name, "scope": mock_scope.external}])][0]["md5"]

        # try to upload file that already exists on RSE and is already registered -> no overwrite
        command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external} --name {file1_name} --file {file4} --register-after-upload"
        exitcode, _, err = execute(command)
        assert exitcode != 0
        remove(file4)
        assert "File already registered" in err


def test_upload_file_guid(rse_factory, rucio_client, mock_scope):
    """CLIENT(USER): Rucio upload file with guid"""
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    guid = generate_uuid()
    command = f"{rcom} -v upload --rse {rse} --guid {guid} --scope {mock_scope.external} --file {file1}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    remove(file1)
    assert len([i for i in rucio_client.list_replicas(dids=[{"name": path.basename(file1), "scope": mock_scope.external}])]) == 1


def test_upload_file_with_impl(rse_factory, rucio_client, mock_scope):
    """CLIENT(USER): Rucio upload file with impl parameter assigned 'posix' value"""
    file1 = file_generator()
    rse, _ = rse_factory.make_posix_rse()
    impl = "posix"
    command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external} --impl {impl} --file {file1}"
    exitcode, out, err = execute(command)
    print(out, err)
    assert exitcode == 0
    assert len([i for i in rucio_client.list_replicas(dids=[{"name": path.basename(file1), "scope": mock_scope.external}])]) == 1


def test_upload_repeated_file(rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Rucio upload repeated files"""
    # One of the files to upload is already catalogued but was removed
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    file2 = file_generator()
    file3 = file_generator()
    file1_name = path.basename(file1)

    command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external}  --file {file1}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # get the rule for the file
    rule_id = [i for i in rucio_client.list_replication_rules(filters={"rse_expression": rse})][0]["id"]
    # delete the file from the catalog
    rucio_client.delete_replication_rule(rule_id)
    # delete the physical file
    command = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(file1_name)
    execute(command)

    command = f"{rcom} -v upload --rse {rse} --scope {mock_scope.external}  --files {file1} {file2} {file3}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    remove(file1)
    remove(file2)
    remove(file3)
    uploaded_replicas = rucio_client.list_replicas(dids=[{"name": path.basename(file), "scope": mock_scope.external} for file in [file1, file2, file3]])
    assert len([i for i in uploaded_replicas]) == 3


def test_upload_repeated_file_dataset(mock_scope, rse_factory, rucio_client):
    """CLIENT(USER): Rucio upload repeated files to dataset"""
    # One of the files to upload is already in the dataset
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    file2 = file_generator()
    file3 = file_generator()
    dataset_name = f"DSet{rse_name_generator()}"
    scope = mock_scope.external

    # Adding files to a new dataset
    command = f"{rcom} -v upload --rse {rse} --scope {scope} --file {file1} --dataset {scope}:{dataset_name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # upload the files to the dataset
    command = f"{rcom} -v upload --rse {rse} --scope {scope} --files {file2} {file3} --dataset {scope}:{dataset_name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # searching for the file in the new dataset
    dataset_contents = rucio_client.list_content(scope=scope, name=dataset_name)
    names = [did["name"] for did in dataset_contents]
    assert path.basename(file2) in names
    assert path.basename(file3) in names

    remove(file1)
    remove(file2)
    remove(file3)


def test_upload_file_dataset(mock_scope, rse_factory, rucio_client):
    """CLIENT(USER): Rucio upload files to dataset"""
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    file2 = file_generator()
    file3 = file_generator()
    dataset_name = f"DSet{rse_name_generator()}"
    scope = mock_scope.external

    # Adding files to a new dataset
    command = f"{rcom} -v upload --rse {rse} --scope {scope} --files {file1} {file2} {file3} --dataset {scope}:{dataset_name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # searching for the file in the new dataset
    dataset_contents = rucio_client.list_content(scope=scope, name=dataset_name)
    names = [did["name"] for did in dataset_contents]
    assert path.basename(file1) in names
    assert path.basename(file2) in names
    assert path.basename(file3) in names

    remove(file1)
    remove(file2)
    remove(file3)


def test_upload_file_dataset_register_after_upload(rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Rucio upload files to dataset with file registration after upload"""
    rse, _ = rse_factory.make_posix_rse()
    file1 = file_generator()
    file2 = file_generator()
    file3 = file_generator()
    dataset_name = f"DSet{rse_name_generator()}"
    scope = mock_scope.external
    rucio_client.add_dataset(scope=scope, name=dataset_name)

    # Adding files to a new dataset
    command = f"{rcom} -v upload --register-after-upload --rse {rse} --scope {scope} --files {file1} {file2} {file3} --dataset {scope}:{dataset_name}"
    exitcode, _, err = execute(command)
    print(err)
    assert exitcode == 0

    # searching for the file in the new dataset
    dataset_contents = rucio_client.list_content(scope=scope, name=dataset_name)
    names = [did["name"] for did in dataset_contents]
    assert path.basename(file1) in names
    assert path.basename(file2) in names
    assert path.basename(file3) in names

    remove(file1)
    remove(file2)
    remove(file3)


def test_upload_adds_md5digest(rse_factory, mock_scope, rucio_client):
    """CLIENT(USER): Upload Checksums"""
    rse, _ = rse_factory.make_posix_rse()
    # user has a file to upload
    filename = file_generator()
    file1_name = path.basename(filename)
    file_md5 = md5(filename)
    scope = mock_scope.external

    # user uploads file
    command = f"{rcom} -v upload --rse {rse} --scope {scope} --files {filename}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    # When inspecting the metadata of the new file the user finds the md5 checksum
    meta = rucio_client.get_metadata(scope=scope, name=file1_name)
    assert "md5" in meta
    assert meta["md5"] == file_md5
    remove(filename)


def test_upload_expiration_date(rse_factory, mock_scope):
    """CLIENT(USER): Rucio upload files"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    file = file_generator()
    command = f"{rcom} -v upload --rse {rse} --scope {scope} --expiration-date 2021-10-10-20:00:00 --lifetime 20000  --files {file}"
    exitcode, _, err = execute(command)
    assert exitcode != 0
    assert "--lifetime and --expiration-date cannot be specified at the same time." in err

    command = f"{rcom} -v upload --rse {rse} --scope {scope} --expiration-date 2021----10-10-20:00:00 --files {file}"
    exitcode, _, err = execute(command)
    assert exitcode != 0
    assert "does not match format '%Y-%m-%d-%H:%M:%S'" in err

    command = f"{rcom} -v upload --rse {rse} --scope {scope} --expiration-date 2021-10-10-20:00:00 --files {file}"
    exitcode, _, err = execute(command)
    assert exitcode != 0
    assert "The specified expiration date should be in the future!" in err

    command = f"{rcom} -v upload --rse {rse} --scope {scope} --expiration-date 2030-10-10-20:00:00 --files {file}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0


def test_download_file(did_factory, rse_factory):
    """CLIENT(USER): Rucio download files"""

    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name
    # download dir_name
    command = f'{rcom} -v download --dir {dir_name} --dids {did["scope"]}:{did["name"]}'
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    downloaded_files = listdir(f"{dir_name.strip('/')}/{did['scope']}/")
    assert did["name"] in downloaded_files
    download_dir.cleanup()


def test_download_pfn(did_factory, rse_factory, rucio_client):
    """CLIENT(USER): Rucio download files"""
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    scope, name = did["scope"].external, did["name"]

    # download files
    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    replica_pfn = list(rucio_client.list_replicas([{"scope": scope, "name": name}]))[0]["rses"][rse][0]

    command = f"{rcom} -v download  --dir {dir_name} --rse {rse} --pfns {replica_pfn}  --dids {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{did['scope']}/")

    download_dir.cleanup()


def test_download_file_with_impl(did_factory, rse_factory):
    """CLIENT(USER): Rucio download files with impl parameter assigned 'posix' value"""
    rse, _ = rse_factory.make_posix_rse()
    did1 = did_factory.upload_test_file(rse)
    scope, name1 = did1["scope"].external, did1["name"]
    did2 = did_factory.upload_test_file(rse)
    name2 = did2["name"]

    impl = "posix"

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    command = f"{rcom} -v download --dir {dir_name} --dids {scope}:{name1} {scope}:{name2} --impl {impl}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    downloads = listdir(f"{dir_name.strip('/')}/{scope}/")
    assert (name1 in downloads) and (name2 in downloads)

    download_dir.cleanup()


def test_download_no_subdir(rse_factory, did_factory):
    """CLIENT(USER): Rucio download files with --no-subdir and check that files already found locally are not replaced"""
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    scope, name = did["scope"].external, did["name"]

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    # download files with --no-subdir
    command = f"{rcom} -v download --no-subdir --dir {dir_name} --dids {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/")

    downloaded_file = f"{dir_name.strip('/')}/{name}"
    original_download_time = path.getmtime(downloaded_file)

    # download again with --no-subdir
    command = f"{rcom} -v download --no-subdir --dir {dir_name} --dids {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Verify it did not re-download
    new_download_time = path.getmtime(downloaded_file)
    assert new_download_time == original_download_time

    download_dir.cleanup()


def test_download_filter(rse_factory, did_factory, rucio_client):
    """CLIENT(USER): Rucio download with filter options"""
    # Use filter option to download file with wildcarded name
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse, return_full_item=True)
    scope, name, uuid = did["did_scope"], did["did_name"], did["guid"]

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    wrong_guid = generate_uuid()
    command = f"{rcom} -v download --dir {dir_name} --dids {scope}:* --filter guid={wrong_guid}"
    exitcode, _, _ = execute(command)
    assert exitcode == 75  # failed to do the requested thing
    assert scope not in listdir(f"{dir_name.strip('/')}/")

    command = f"{rcom} -v download --dir {dir_name} --dids {scope}:* --filter guid={uuid}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{scope}")

    # try without specifying the did
    did = did_factory.upload_test_file(rse, return_full_item=True)
    scope, name, uuid = did["did_scope"], did["did_name"], did["guid"]
    command = f"{rcom} -v download --dir {dir_name} --scope {scope} --filter guid={uuid}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{scope}")

    new_mock_scope = scope_name_generator()
    rucio_client.add_scope("root", new_mock_scope)
    did = did_factory.upload_test_file(scope=new_mock_scope, rse_name=rse)
    scope, name = did["scope"].external, did["name"]
    command = f"{rcom} download --dir {dir_name} --scope {scope} --filter created_after=1900-01-01T00:00:00.000Z"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{scope}")

    # Use filter option to download dataset with wildcarded name
    command = f"{rcom} download --dir {dir_name} --dids {scope}:* --filter created_after=1900-01-01T00:00:00.000Z"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{scope}")

    download_dir.cleanup()


def test_download_timeout_options_accepted(rse_factory, did_factory):
    """CLIENT(USER): Rucio download timeout options"""
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse_name=rse)
    scope, name = did["scope"].external, did["name"]

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    command = f"{rcom} -v download --dir {dir_name} --transfer-timeout 3 --transfer-speed-timeout 1000 --dids {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{scope}")

    # Check that PFN the transfer-speed-timeout option is not accepted for --pfn
    did = did_factory.upload_test_file(rse_name=rse)
    scope, name = did["scope"].external, did["name"]
    command = f"{rcom} -v download --dir {dir_name} --rse {rse} --transfer-speed-timeout 1 --pfns http://a.b.c/ --dids {scope}:{name}"
    exitcode, _, err = execute(command)
    assert exitcode != 0
    assert "Download with --pfns doesn't support --transfer" in err
    assert name not in listdir(f"{dir_name.strip('/')}/{scope}")

    download_dir.cleanup()


def test_download_metalink_file(rse_factory, did_factory, rucio_client):
    """CLIENT(USER): Rucio download with metalink file"""

    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    scope, name = did["scope"].external, did["name"]
    metalink_file = tempfile.NamedTemporaryFile(dir="./", prefix="metalink")
    metalink_file_path = metalink_file.name

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    # Use filter and metalink option
    command = f"{rcom} download --scope mock --filter size=1 --metalink {metalink_file_path}"
    exitcode, _, err = execute(command)
    assert exitcode != 0
    assert "Arguments filter and metalink cannot be used together" in err

    # Use did and metalink option
    command = f"{rcom} -v download --metalink {metalink_file_path} --dids {scope}:{name}"
    exitcode, _, err = execute(command)
    assert exitcode != 0
    assert "Arguments dids and metalink cannot be used together" in err

    # Download only with metalink file
    replica_file = rucio_client.list_replicas([{"scope": scope, "name": name}], metalink=True)
    with open(metalink_file_path, "w+") as fp:
        fp.write(replica_file)

    command = f"{rcom} -v download --dir {dir_name} --metalink {metalink_file_path}"
    exitcode, _, err = execute(command)
    print(err)
    assert exitcode == 0
    assert name in listdir(f"{dir_name.strip('/')}/{scope}")

    metalink_file.close()
    download_dir.cleanup()


def test_download_dataset(rse_factory, did_factory, rucio_client):
    """CLIENT(USER): Rucio download dataset"""

    # create dataset
    scope = scope_name_generator()
    rucio_client.add_scope("root", scope)
    dataset = did_factory.make_dataset(scope)
    name = dataset["name"]

    # add files
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse, scope=scope)

    # add files to dataset
    rucio_client.attach_dids(scope, name, dids=[did])

    # download dataset
    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    command = f"{rcom} -v download --no-subdir --dir {dir_name} --dids {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert did["name"] in listdir(f"{dir_name.strip('/')}")
    download_dir.cleanup()


def test_download_file_check_by_size(rse_factory, did_factory):
    """CLIENT(USER): Rucio download files"""
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    scope, name = did["scope"], did["name"]

    download_dir = tempfile.TemporaryDirectory(dir="./")
    dir_name = download_dir.name

    command = f"{rcom} -v download --dir {dir_name} --dids {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    # Alter downloaded file
    command = f'echo "dummy" >> {dir_name.strip("/")}/{scope}/{name}'
    assert exitcode == 0
    # Download file again and check for mismatch
    command = f"{rcom} -v download --check-local-with-filesize --dir {dir_name} --dids {scope}:{name}"
    exitcode, _, err = execute(command)
    assert exitcode == 0
    assert "File exists already locally" in err

    download_dir.cleanup()
