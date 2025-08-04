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
import logging
import os
import shutil
from random import choice
from string import ascii_uppercase
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from rucio.client.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common.checksum import adler32, md5
from rucio.common.config import config_add_section, config_set
from rucio.common.constants import RseAttr
from rucio.common.exception import InputValidationError, NoFilesUploaded, NotAllFilesUploaded, ResourceTemporaryUnavailable
from rucio.common.types import InternalScope
from rucio.common.utils import execute, generate_uuid
from rucio.core.rse import add_protocol, add_rse_attribute
from rucio.tests.common import did_name_generator

if TYPE_CHECKING:
    from rucio.common.types import FileToUploadDict


@pytest.fixture
def upload_client():
    logger = logging.getLogger('upload_client')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
    return UploadClient(logger=logger)


@pytest.fixture
def rse(containerized_rses, rse_factory):
    if len(containerized_rses) > 0:
        rse, _ = containerized_rses[0]
    else:
        rse, _ = rse_factory.make_posix_rse()
    return rse


@pytest.fixture
def scope(vo, containerized_rses, test_scope, mock_scope):
    if len(containerized_rses) > 0:
        return str(test_scope)
    else:
        return str(mock_scope)


@pytest.mark.parametrize("file_config_mock", [
    {},  # Use rucio.cfg as-is.
    pytest.param(
        {  # Remove "account" from the "[client]" section.
            "removes": [('client', 'account')]
        }, marks=pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'multi_vo', reason="See https://github.com/rucio/rucio/issues/7394"))
    ], indirect=True)
def test_upload_single(file_config_mock, rse, scope, upload_client, download_client, file_factory):
    local_file = file_factory.file_generator()
    download_dir = file_factory.base_dir
    fn = os.path.basename(local_file)

    item: FileToUploadDict = {
        'path': local_file,
        'rse': rse,
        'did_scope': scope,
        'did_name': fn,
        'guid': generate_uuid()
    }

    # upload a file
    status = upload_client.upload(items=[item])
    assert status == 0

    # download the file
    did = f"{scope}:{fn}"
    download_client.download_dids([{'did': did, 'base_dir': download_dir}])

    # match checksums
    downloaded_file = f"{download_dir}/{scope}/{fn}"
    assert adler32(local_file) == adler32(downloaded_file)


def test_upload_multi(rse, scope, upload_client, download_client, file_factory):
    local_file1 = file_factory.file_generator(use_basedir=True)
    local_file2 = file_factory.file_generator(use_basedir=True)
    download_dir = file_factory.base_dir

    fn1 = os.path.basename(local_file1)
    fn2 = os.path.basename(local_file2)

    items: list[FileToUploadDict] = [
        {
            'path': local_file1,
            'rse': rse,
            'did_scope': scope,
            'did_name': fn1,
            'guid': generate_uuid(),
        },
        {
            'path': local_file2,
            'rse': rse,
            'did_scope': scope,
            'did_name': fn2,
            'guid': generate_uuid(),
        },
    ]

    status = upload_client.upload(items=items)
    assert status == 0
    # download the files
    did1 = f"{scope}:{fn1}"
    did2 = f"{scope}:{fn2}"
    download_client.download_dids([
        {'did': did1, 'base_dir': download_dir},
        {'did': did2, 'base_dir': download_dir}
    ])

    # match checksums
    downloaded_file1 = f"{download_dir}/{scope}/{fn1}"
    assert adler32(local_file1) == adler32(downloaded_file1)

    downloaded_file2 = f"{download_dir}/{scope}/{fn2}"
    assert adler32(local_file2) == adler32(downloaded_file2)


def test_upload_file_already_exists_single(rse, scope, upload_client, file_factory):
    traces = []
    local_file = file_factory.file_generator()

    item: FileToUploadDict = {
        'path': local_file,
        'rse': rse,
        'did_scope': scope,
    }

    # upload the file
    upload_client.upload(items=[item])
    # re_upload the file
    with pytest.raises(NoFilesUploaded):
        upload_client.upload(items=[item], traces_copy_out=traces)
    assert len(traces) == 1 and traces[0]['stateReason'] == 'File already exists'


def test_upload_file_already_exists_multi(rse, scope, upload_client, file_factory):
    traces = []
    local_file = file_factory.file_generator()

    items: list[FileToUploadDict] = [
        {
            'path': local_file,
            'rse': rse,
            'did_scope': scope,
        },
        {
            'path': local_file,
            'rse': rse,
            'did_scope': scope,
        }
    ]

    # upload the file twice in the same upload command
    with pytest.raises(NotAllFilesUploaded):
        upload_client.upload(items=items, traces_copy_out=traces)

    assert len(traces) == 2 and traces[1]['stateReason'] == 'File already exists'


def test_upload_source_not_found(rse, scope, upload_client):
    item: FileToUploadDict = {
        'path': 'non_existent_local_file',
        'rse': rse,
        'did_scope': scope,
    }

    with pytest.raises(InputValidationError):
        upload_client.upload(items=[item])


def test_multiple_protocols_same_scheme(rse_factory, upload_client, mock_scope, file_factory):
    """ Upload (CLIENT): Ensure domain correctly selected when multiple protocols exist with the same scheme """

    rse, rse_id = rse_factory.make_rse()

    # Ensure client site and rse site are identical. So that "lan" is preferred.
    add_rse_attribute(rse_id, RseAttr.SITE, 'ROAMING')

    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': 'file-wan.aperture.com',
                          'port': 0,
                          'prefix': '/prefix1/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': None, 'write': None, 'delete': None},
                              'wan': {'read': 0, 'write': 0, 'delete': 0}}})
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': 'file-lan.aperture.com',
                          'port': 0,
                          'prefix': '/prefix2/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 0, 'write': 0, 'delete': 0},
                              'wan': {'read': None, 'write': None, 'delete': None}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': 'root.aperture.com',
                          'port': 1403,
                          'prefix': '/prefix3/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})

    # Upload a file
    path = file_factory.file_generator()
    name = os.path.basename(path)

    item: FileToUploadDict = {
        'path': path,
        'rse': rse,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid(),
    }
    summary_path = file_factory.base_dir / 'summary'
    upload_client.upload(items=[item], summary_file_path=summary_path)

    # Verify that the lan protocol was used for the upload
    with open(summary_path) as json_file:
        data = json.load(json_file)
        assert 'file-lan.aperture.com' in data['{}:{}'.format(mock_scope, name)]['pfn']


def test_upload_file_with_impl(rse_factory, upload_client, mock_scope, file_factory):
    """ Upload (CLIENT): Ensure the module associated to the impl value is called """

    impl = 'xrootd'
    rse_name, rse_id = rse_factory.make_rse()

    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 0, 'write': 0, 'delete': 0},
                              'wan': {'read': 0, 'write': 0, 'delete': 0}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})

    path = file_factory.file_generator()
    name = os.path.basename(path)

    item: FileToUploadDict = {
        'path': path,
        'rse': rse_name,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid(),
        'impl': impl
    }

    with TemporaryDirectory() as tmp_dir:
        with patch('rucio.rse.protocols.%s.Default.put' % impl, side_effect=lambda pfn, dest, dir, **kw: shutil.copy(path, tmp_dir)) as mock_put, \
                patch('rucio.rse.protocols.%s.Default.connect' % impl), \
                patch('rucio.rse.protocols.%s.Default.exists' % impl, side_effect=lambda pfn, **kw: False), \
                patch('rucio.rse.protocols.%s.Default.delete' % impl), \
                patch('rucio.rse.protocols.%s.Default.rename' % impl), \
                patch('rucio.rse.protocols.%s.Default.stat' % impl, side_effect=lambda pfn: {'filesize': os.stat(path)[os.path.stat.ST_SIZE], 'adler32': adler32(path)}), \
                patch('rucio.rse.protocols.%s.Default.close' % impl):
            mock_put.__name__ = "mock_put"
            upload_client.upload(items=[item])
            mock_put.assert_called()


def test_upload_file_with_supported_protocol(rse_factory, upload_client, mock_scope, file_factory):
    """ Upload (CLIENT): Ensure the module associated to the first protocol supported by both the remote and local config is called """

    rse_name, rse_id = rse_factory.make_rse()

    # FIXME:
    # The correct order to test should actually be ssh,xrootd,posix
    # However the preferred_impl is not working correctly.
    # Once preferred_impl is fixed, this should be changed back
    add_protocol(rse_id, {'scheme': 'scp',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 0, 'write': 0, 'delete': 0},
                              'wan': {'read': 0, 'write': 0, 'delete': 0}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.ssh.Default',
                          'domains': {
                              'lan': {'read': 2, 'write': 2, 'delete': 2},
                              'wan': {'read': 2, 'write': 2, 'delete': 2}}})

    path = file_factory.file_generator()
    name = os.path.basename(path)

    item: FileToUploadDict = {
        'path': path,
        'rse': rse_name,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid()
    }

    status = upload_client.upload(items=[item])
    assert status == 0


def test_upload_file_with_supported_protocol_from_config(rse_factory, upload_client, mock_scope, file_factory):
    """ Upload (CLIENT): Ensure the module associated to the first protocol supported by both the remote and local config read from rucio.cfg is called """

    rse_name, rse_id = rse_factory.make_rse()

    # FIXME:
    # The correct order to test should actually be ssh,xrootd,posix
    # However the preferred_impl is not working correctly.
    # Once preferred_impl is fixed, this should be changed back
    add_protocol(rse_id, {'scheme': 'scp',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 0, 'write': 0, 'delete': 0},
                              'wan': {'read': 0, 'write': 0, 'delete': 0}}})
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.ssh.Default',
                          'domains': {
                              'lan': {'read': 2, 'write': 2, 'delete': 2},
                              'wan': {'read': 2, 'write': 2, 'delete': 2}}})

    config_add_section('upload')
    config_set('upload', 'preferred_impl', 'rclone, xrootd')

    supported_impl = 'xrootd'

    path = file_factory.file_generator()
    name = os.path.basename(path)

    item: FileToUploadDict = {
        'path': path,
        'rse': rse_name,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid()
    }

    with TemporaryDirectory() as tmp_dir:
        with patch('rucio.rse.protocols.%s.Default.put' % supported_impl, side_effect=lambda pfn, dest, dir, **kw: shutil.copy(path, tmp_dir)) as mock_put, \
                patch('rucio.rse.protocols.%s.Default.connect' % supported_impl), \
                patch('rucio.rse.protocols.%s.Default.exists' % supported_impl, side_effect=lambda pfn, **kw: False), \
                patch('rucio.rse.protocols.%s.Default.delete' % supported_impl), \
                patch('rucio.rse.protocols.%s.Default.rename' % supported_impl), \
                patch('rucio.rse.protocols.%s.Default.stat' % supported_impl, side_effect=lambda pfn: {'filesize': os.stat(path)[os.path.stat.ST_SIZE], 'adler32': adler32(path)}), \
                patch('rucio.rse.protocols.%s.Default.close' % supported_impl):
            mock_put.__name__ = "mock_put"
            upload_client.upload(items=[item])
            mock_put.assert_called()


def test_upload_file_ignore_availability(rse_factory, scope, upload_client, file_factory, rucio_client):
    rse, rse_id = rse_factory.make_posix_rse()
    rucio_client.update_rse(rse, {'availability_write': False})
    local_file = file_factory.file_generator()

    item: FileToUploadDict = {
        'path': local_file,
        'rse': rse,
        'did_scope': scope,
    }

    status = upload_client.upload(items=[item], ignore_availability=True)
    assert status == 0


@pytest.fixture
def upload_client_registration_fail():
    logger = logging.getLogger('upload_client')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    # modify the client object used by upload_client so that replica registration fails
    class RegistrationFailureClient(Client):

        def __init__(self, **args):
            super(RegistrationFailureClient, self).__init__(**args)

        def update_replicas_states(self, rse, files):
            # simulate server timing out
            raise ResourceTemporaryUnavailable

    return UploadClient(logger=logger, _client=RegistrationFailureClient())


def test_upload_registration_fail(rse, scope, upload_client_registration_fail, file_factory):
    local_file = file_factory.file_generator()
    fn = os.path.basename(local_file)

    # upload a file and check that exception is raised
    with pytest.raises(NoFilesUploaded):
        item: FileToUploadDict = {
            'path': local_file,
            'rse': rse,
            'did_scope': scope,
            'did_name': fn,
            'guid': generate_uuid()
        }

        upload_client_registration_fail.upload(items=[item])


@pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'client', reason="Requires DB access")
def test_upload_file_register_after_upload(rse, scope, upload_client, rucio_client, file_factory, vo):
    """CLIENT(USER): Rucio upload files with registration after upload"""
    local_file1 = file_factory.file_generator()
    local_file2 = file_factory.file_generator()
    local_file3 = file_factory.file_generator()

    local_file1_name = os.path.basename(local_file1)
    local_file2_name = os.path.basename(local_file2)
    local_file3_name = os.path.basename(local_file3)

    status = upload_client.upload([
        {
            "did_scope": scope,
            "rse": rse,
            "did_name": fn,
            "path": path,
            "register_after_upload": True
        }
        for fn, path in zip([local_file1_name, local_file2_name, local_file3_name], [local_file1, local_file2, local_file3])
    ])
    assert status == 0

    # Trying to upload again produces an error
    with pytest.raises(NoFilesUploaded):
        upload_client.upload([
            {
                "did_scope": scope,
                "rse": rse,
                "did_name": local_file1_name,
                "path": local_file1,
            }
        ])

    # removing replica -> file on RSE should be overwritten
    # (simulating an upload error, where a part of the file is uploaded but the replica is not registered)
    from sqlalchemy import and_, delete

    from rucio.db.sqla import models, session

    db_session = session.get_session()
    internal_scope = InternalScope(scope, vo=vo)
    for model in [models.RSEFileAssociation, models.ReplicaLock, models.ReplicationRule, models.DidMeta, models.DataIdentifier]:
        stmt = delete(
            model
        ).where(
            and_(
                model.name == local_file1_name,
                model.scope == internal_scope)
            )
        db_session.execute(stmt)
    db_session.commit()

    # After removing the replica, you can upload with the replica name however you like
    local_file4 = file_factory.file_generator()
    upload_client.upload([
        {"did_scope": scope, "rse": rse, "did_name": local_file1_name, "path": local_file4, "register_after_upload": True}])
    assert md5(local_file4) == [replica for replica in rucio_client.list_replicas(dids=[{'name': local_file1_name, 'scope': scope}])][0]['md5']


@pytest.mark.xfail(reason="Permission error needs to be resolved")
def test_upload_repeat_after_deletion(file_factory, rse_factory, upload_client, scope, rucio_client):
    """CLIENT(USER): Rucio upload repeated files"""
    # One of the files to upload is already catalogued but was removed
    rse, _ = rse_factory.make_posix_rse()

    local_file1 = file_factory.file_generator()
    local_file1_name = os.path.basename(local_file1)

    upload_client.upload([
        {
            "did_scope": scope,
            "rse": rse,
            "did_name": local_file1_name,
            "path": local_file1,
        }
    ])

    # Find and delete the rule
    print([f for f in rucio_client.list_replication_rules({'name': local_file1_name})])
    rule_id = [f['id'] for f in rucio_client.list_replication_rules({'name': local_file1_name})][0]
    rucio_client.delete_replication_rule(rule_id)

    # Delete the file from the RSE
    # ??? Why does root not have permission to delete the file?
    rucio_client.delete_replicas(rse, [{'scope': scope, 'name': local_file1_name}])

    # File can be re-uploaded
    status = upload_client.upload([
        {
            "did_scope": scope,
            "rse": rse,
            "did_name": local_file1_name,
            "path": local_file1,
        }
    ])
    assert status == 0


def test_upload_repeated_file_dataset(file_factory, rse_factory, rucio_client, upload_client, scope):
    """CLIENT(USER): Rucio upload repeated files to dataset"""
    # One of the files to upload is already in the dataset

    rse, _ = rse_factory.make_posix_rse()
    tmp_file1 = file_factory.file_generator()
    tmp_file2 = file_factory.file_generator()

    tmp_file1_name = os.path.basename(tmp_file1)
    tmp_file2_name = os.path.basename(tmp_file2)

    tmp_dataset = f"DSet{generate_uuid()}"
    # User uploads a dataset with a single file
    status = upload_client.upload([
        {"dataset_name": tmp_dataset, "dataset_scope": scope, "path": tmp_file1, "rse": rse, "did_scope": scope, "did_name": tmp_file1_name}
    ])
    assert status == 0

    # Other files are added to the same dataset
    status = upload_client.upload([
        {"dataset_name": tmp_dataset, "dataset_scope": scope, "path": tmp_file2, "rse": rse, "did_scope": scope, "did_name": tmp_file2_name}
    ])
    assert status == 0
    # All files are added to the same dataset
    files = [f['name'] for f in rucio_client.list_files(scope=scope, name=tmp_dataset)]
    assert tmp_file1_name in files
    assert tmp_file2_name in files


def test_upload_adds_md5digest(file_factory, rse_factory, rucio_client, upload_client, scope):
    """CLIENT(USER): Upload Checksums"""
    # user has a file to upload
    rse, _ = rse_factory.make_posix_rse()
    tmp_file = file_factory.file_generator()
    tmp_file_name = os.path.basename(tmp_file)
    file_md5 = md5(tmp_file)
    # user uploads file
    upload_client.upload([
        {
            "did_scope": scope,
            "rse": rse,
            "did_name": tmp_file_name,
            "path": tmp_file,
        }
    ])

    meta = rucio_client.get_metadata(scope=scope, name=tmp_file_name)
    assert 'md5' in meta
    assert meta['md5'] == file_md5


def test_upload_recursive_preserve_structure(rse_factory, rucio_client, upload_client, scope):
    """CLIENT(USER): Upload and preserve folder structure"""
    rse, _ = rse_factory.make_posix_rse()
    with TemporaryDirectory() as tmp_dir:
        folder1 = '%s/folder_%s' % (tmp_dir, generate_uuid())
        folder2 = '%s/folder_%s' % (tmp_dir, generate_uuid())
        folder3 = '%s/folder_%s' % (tmp_dir, generate_uuid())
        folder11 = '%s/folder_%s' % (folder1, generate_uuid())
        folder12 = '%s/folder_%s' % (folder1, generate_uuid())
        folder13 = '%s/folder_%s' % (folder1, generate_uuid())
        file1 = 'file_%s' % generate_uuid()
        file2 = 'file_%s' % generate_uuid()

        os.makedirs(folder1)
        os.makedirs(folder2)
        os.makedirs(folder3)
        os.makedirs(folder11)
        os.makedirs(folder12)
        os.makedirs(folder13)

        with open('%s/%s' % (folder11, file1), 'w') as f:
            f.write(generate_uuid())
        with open('%s/%s' % (folder2, file2), 'w') as f:
            f.write(generate_uuid())

        status = upload_client.upload([
            {
                "did_scope": scope,
                "path": tmp_dir,
                "recursive": True,
                "rse": rse,
            }
        ])
        assert status == 0

        contents = [f['name'] for f in rucio_client.list_content(scope=scope, name=tmp_dir.split('/')[-1])]
        assert len(contents) == 2
        assert folder1.split('/')[-1] in contents
        assert folder2.split('/')[-1] in contents
        assert folder3.split('/')[-1] not in contents  # Folder 3 is empty, and is skipped during upload

        contents = [f['name'] for f in rucio_client.list_content(scope=scope, name=folder1.split('/')[-1])]
        assert len(contents) == 1
        assert folder11.split('/')[-1] in contents
        assert folder12.split('/')[-1] not in contents  # 12 and 13 are empty, and are skipped during upload
        assert folder13.split('/')[-1] not in contents

        contents = [f['name'] for f in rucio_client.list_content(scope=scope, name=folder11.split('/')[-1])]
        assert len(contents) == 1
        assert file1 in contents

        contents = [f['name'] for f in rucio_client.list_content(scope=scope, name=folder2.split('/')[-1])]
        assert len(contents) == 1
        assert file2 in contents


@pytest.mark.parametrize("structure,is_valid_container", [
    ({"bad_container": ["file1", "file2", {"dataset": ["file3", "file4"]}]}, False),  # Cannot have both files and datasets in a container
    ({
        "valid_container": {
            "dataset": ["file1", "file2"]
            },
        "bad_container": {
            "dataset": ["file1", {"bad_dataset": ["file1"]}]
        }
    }, False),  # One valid container, another invalid container
    ({
        "container": {
            "bad_container": {
                "dataset": {
                    "bad_dataset": ["file1", {"dataset": ["file2"]}]}}},
    }, False),  # Same issue but further down the tree
    ({"valid_container": {"dataset": ["file1"], "dataset2": ["file2"]}}, True),  # One valid container
    ({
        "valid_container": {"dataset": ["file1"], "dataset2": ["file2"]},
        "valid_container2": {"dataset": ["file1"], "dataset2": ["file2"]}
    }, True),  # Two valid containers
    ({
        "valid_container": {
            "nested_valid_container": {"dataset": ["file1"]},
            "nested_valid_container2": {"dataset": ["file2"]}}
    },  # Nested valid containers
        True
    )
],
    ids=[
        "Single invalid container",
        "Invalid container container paired with valid container",
        "Nested invalid container",
        "Valid single container",
        "Multiple valid container",
        "Nested valid containers"
])
def test_upload_recursive(structure, is_valid_container, rse_factory, scope, upload_client):
    """
    Ensure logic for recursive uploads.

    Containers only contain collection DIDs of one type, and never files. Datasets only contain files or other datasets, but not at the same time.
    """

    def recursive_create(dir_path, contents):
        for value in contents.values():
            directory = did_name_generator()

            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        file_path = os.path.join(dir_path, directory,  ''.join(choice(ascii_uppercase) for _ in range(5)))
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        execute(f'dd if=/dev/urandom of={file_path} count={2} bs=1')

                    elif isinstance(item, dict):
                        subdir = did_name_generator()
                        sub_dir_path = os.path.join(dir_path, directory, subdir)
                        os.makedirs(sub_dir_path, exist_ok=True)
                        recursive_create(sub_dir_path, item)
                    else:
                        raise ValueError(f"Invalid item type: {type(item)} in structure")

            else:
                # item is a subdirectory
                sub_dir_path = os.path.join(dir_path, directory)
                os.makedirs(sub_dir_path, exist_ok=True)
                recursive_create(sub_dir_path, value)

    with TemporaryDirectory() as tmp_dir:

        recursive_create(tmp_dir, structure)

        rse, _ = rse_factory.make_posix_rse()
        items = {
            'path': tmp_dir,
            'rse': rse,
            'did_scope': scope,
            'did_name': os.path.basename(tmp_dir),
            'recursive': True,
        }
        if not is_valid_container:
            with pytest.raises(InputValidationError):
                upload_client._collect_files_recursive(items)
        else:
            upload_client._collect_files_recursive(items)
