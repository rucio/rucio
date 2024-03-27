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

import logging
import os
from tempfile import TemporaryDirectory

import pytest

from rucio.client.downloadclient import DownloadClient
from rucio.client.s3client import S3Client
from rucio.common.utils import generate_uuid
from rucio.tests.common import load_test_conf_file
from tests.test_download import _check_download_result


@pytest.fixture
def s3_client():
    logger = logging.getLogger("s3_client")
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
    config = load_test_conf_file("s3client.cfg.template")
    return S3Client(logger=logger, config=config)


@pytest.fixture
def download_client():
    return DownloadClient()


def test_create_bucket(s3_client):
    """S3CLIENT: Create a bucket"""
    # TODO: add more scopes for validation
    scope = "user.dquijote:/folder/"
    status = s3_client.bucket_create(scope)
    assert status == 0


def test_upload_download_bucket(s3_client, file_factory):
    """S3CLIENT: Upload a bucket"""
    scope = "user.dquijote:/folder/"
    local_file = str(file_factory.file_generator())
    fn = str(os.path.basename(local_file))
    did_name = scope + fn
    base_name = generate_uuid()
    s3_client.bucket_upload(from_path=local_file, to_path=scope)

    with TemporaryDirectory() as tmp_dir:
        result = download_client.download_dids(
            [{"did": "%s:%s.*" % (scope, base_name), "base_dir": tmp_dir}]
        )
        # triggers s3_client.bucket_download(from_path=scope + fn, to_path=tmp_dir)
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    "did": did_name,
                    "clientState": "DONE",
                }
            ],
        )


def test_upload_bucket_fail(s3_client, file_factory):
    """S3CLIENT: Upload a bucket"""
    pass
