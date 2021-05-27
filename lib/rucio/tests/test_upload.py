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

import logging
import pytest
import os
import shutil
from rucio.client.downloadclient import DownloadClient
from rucio.client.uploadclient import UploadClient
from rucio.tests.common import file_generator
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


def test_upload_single(rse, scope, upload_client, download_client):
    local_file = file_generator()
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
    try:
        # download the file
        did = f"{scope}:{fn}"
        download_client.download_dids([{'did': did}])

        # match checksums
        downloaded_file = f"./{scope}/{fn}"
        assert adler32(local_file) == adler32(downloaded_file)

    finally:
        os.remove(local_file)
        shutil.rmtree(scope)


@pytest.mark.noparallel(reason="Fails when run in parallel")
def test_upload_multi(rse, scope, upload_client, download_client):
    local_file1 = file_generator()
    local_file2 = file_generator()
    fn1 = os.path.basename(local_file1)
    fn2 = os.path.basename(local_file2)
    try:
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
        download_client.download_dids([{'did': did1}, {'did': did2}])

        # match checksums
        downloaded_file1 = f"./{scope}/{fn1}"
        assert adler32(local_file1) == adler32(downloaded_file1)

        downloaded_file2 = f"./{scope}/{fn2}"
        assert adler32(local_file2) == adler32(downloaded_file2)

    finally:
        os.remove(local_file1)
        os.remove(local_file2)
        shutil.rmtree(scope)


def test_upload_file_already_exists_single(rse, scope, upload_client):
    traces = []
    local_file = file_generator()
    try:
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
    finally:
        os.remove(local_file)


@pytest.mark.noparallel(reason="Fails when run in parallel")
def test_upload_file_already_exists_multi(rse, scope, upload_client):
    traces = []
    local_file = file_generator()
    try:
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
    finally:
        os.remove(local_file)


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
