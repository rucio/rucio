# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
import json
import logging
import pytest
import os
from rucio.client.downloadclient import DownloadClient
from rucio.core.rse import add_protocol, add_rse_attribute
from rucio.client.uploadclient import UploadClient
from rucio.common.exception import NotAllFilesUploaded, NoFilesUploaded, InputValidationError
from rucio.common.utils import generate_uuid
from rucio.common.utils import adler32


@pytest.fixture
def upload_client():
    logger = logging.getLogger('upload_client')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
    return UploadClient(logger=logger)


@pytest.fixture
def download_client():
    return DownloadClient()


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


def test_upload_single(rse, scope, upload_client, download_client, file_factory):
    local_file = file_factory.file_generator()
    download_dir = file_factory.base_dir
    fn = os.path.basename(local_file)

    # upload a file
    status = upload_client.upload([{
        'path': local_file,
        'rse': rse,
        'did_scope': scope,
        'did_name': fn,
        'guid': generate_uuid()
    }])
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

    items = [
        {
            'path': local_file1,
            'rse': rse,
            'did_scope': scope,
            'did_name': fn1,
            'guid': generate_uuid()
        },
        {
            'path': local_file2,
            'rse': rse,
            'did_scope': scope,
            'did_name': fn2,
            'guid': generate_uuid()
        }
    ]

    status = upload_client.upload(items)
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

    item = [
        {
            'path': local_file,
            'rse': rse,
            'did_scope': scope,
        }
    ]
    # upload the file
    upload_client.upload(item)
    # re_upload the file
    with pytest.raises(NoFilesUploaded):
        upload_client.upload(item, traces_copy_out=traces)
    assert len(traces) == 1 and traces[0]['stateReason'] == 'File already exists'


def test_upload_file_already_exists_multi(rse, scope, upload_client, file_factory):
    traces = []
    local_file = file_factory.file_generator()

    items = [
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
        upload_client.upload(items, traces_copy_out=traces)

    assert len(traces) == 2 and traces[1]['stateReason'] == 'File already exists'


def test_upload_source_not_found(rse, scope, upload_client):
    items = [
        {
            'path': 'non_existant_local_file',
            'rse': rse,
            'did_scope': scope,
        }
    ]
    with pytest.raises(InputValidationError):
        upload_client.upload(items)


def test_multiple_protocols_same_scheme(rse_factory, upload_client, mock_scope, file_factory):
    """ Upload (CLIENT): Ensure domain correctly selected when multiple protocols exist with the same scheme """

    rse, rse_id = rse_factory.make_rse()

    # Ensure client site and rse site are identical. So that "lan" is preferred.
    add_rse_attribute(rse_id, 'site', 'ROAMING')

    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': 'file-wan.aperture.com',
                          'port': 0,
                          'prefix': '/prefix1/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 0, 'write': 0, 'delete': 0},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': 'file-lan.aperture.com',
                          'port': 0,
                          'prefix': '/prefix2/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 0, 'write': 0, 'delete': 0}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': 'root.aperture.com',
                          'port': 1403,
                          'prefix': '/prefix3/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 2, 'write': 2, 'delete': 2},
                              'wan': {'read': 2, 'write': 2, 'delete': 2}}})

    # Upload a file
    path = file_factory.file_generator()
    name = os.path.basename(path)
    item = {
        'path': path,
        'rse': rse,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid(),
    }
    summary_path = file_factory.base_dir / 'summary'
    upload_client.upload([item], summary_file_path=summary_path)

    # Verify that the lan protocol was used for the upload
    with open(summary_path) as json_file:
        data = json.load(json_file)
        assert 'file-lan.aperture.com' in data['{}:{}'.format(mock_scope, name)]['pfn']
