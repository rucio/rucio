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

from rucio.client.client import Client
from rucio.common.cache import make_region_memcached
from rucio.common.config import get_s3_credentials
from rucio.common.exception import (
    ScopeNotFound,
    DataIdentifierAlreadyExists,
    UnsupportedOperation,
)

import boto3
from botocore.exceptions import ClientError
from dogpile.cache.api import NO_VALUE


REGION = make_region_memcached(expiration_time=900)


class S3Client:
    """S3 client class"""

    S3_BASEURL = "s3"

    def __init__(self, _client=None, logger=None, config: dict = None):
        # TODO: use boto3 Session instead of client
        """
        Initialises the basic settings for an S3Client object

        :param _client:     - Optional:  rucio.client.client.Client object. If None, a new object will be created.
        :param logger:      - Optional:  logging.Logger object. If None, default logger will be used.
        :param config:      - Optional:  dict object with S3 credentials. If None, credentials will be loaded from default bucket_path.

        """

        if not logger:
            self.logger = logging.log
        else:
            self.logger = logger.log

        self.client = _client if _client else Client()
        account = self.client.account
        cred = REGION.get("s3client-%s" % account)
        if cred is NO_VALUE:
            if config:
                cred = config
            else:
                cred = get_s3_credentials()
            REGION.set("s3client-%s" % account, cred)
        try:
            self.s3 = boto3.client("s3", **cred, verify=False)
        except Exception as error:
            self.logger(logging.ERROR, error)
            raise error

    def bucket_create(self, bucket_path):
        """Create an S3 bucket.

        param bucket_path: Bucket bucket_path, e.g. user.dquijote:/mybucket/
        :return: True if bucket created, else False
        """
        # TODO: IAM policy structure
        # TODO: Use boto3.Session to load .aws/credentials automatically if found
        logger = self.logger
        bucket_name, folder = bucket_path.split(":")

        # create did

        try:
            self.s3.head_bucket(Bucket=bucket_name)
        except ClientError as error:
            if error.response["Error"]["Code"] == "404":
                logger(logging.DEBUG, "Creating bucket %s" % bucket_name)
                self.s3.create_bucket(Bucket=bucket_name)
            elif error.response["Error"]["Code"] == "409":
                # Bucket already exists, no need to raise exception
                pass
            else:
                logger(logging.ERROR, error.response["Error"]["Message"])

        try:
            self.s3.put_object(Bucket=bucket_name, Body="", Key=folder)
        except ClientError as error:
            logger(logging.ERROR, error.response["Error"]["Message"])
            raise error

    def bucket_upload(self, from_path, to_path):
        """Upload a file/folder to an S3 bucket.

        :param from_path: Path to the file/folder to upload
        :param to_path: Bucket path, e.g. user.dquijote:/mybucket/file.ext or user.dquijote:/mybucket/folder/
        :return: True if file/folder uploaded, else False
        """
        logger = self.logger
        bucket_name, bucket_path = to_path.split(":")

        if from_path.endswith("/") and to_path.endswith("/"):
            for root, dirs, files in os.walk(from_path):
                for file in files:
                    try:
                        with open(os.path.join(root, file), "rb") as f:
                            destination = (
                                bucket_path + file
                                if to_path.endswith("/")
                                else bucket_path
                            )
                            self.s3.upload_fileobj(
                                Fileobj=f, Bucket=bucket_name, Key=str(destination)
                            )
                    except FileNotFoundError as error:
                        logger(logging.ERROR, "File not found")
                        raise error
                    except ClientError as error:
                        logger(logging.ERROR, error)
                        raise error

        elif from_path.endswith("/") and not to_path.endswith("/"):
            raise UnsupportedOperation()
        else:  # file -> file or file -> folder
            try:
                with open(from_path, "rb") as f:
                    destination = (
                        bucket_path + os.path.basename(from_path)
                        if bucket_path.endswith("/")
                        else bucket_path
                    )
                    self.s3.upload_fileobj(
                        Fileobj=f, Bucket=bucket_name, Key=str(destination)
                    )
            except FileNotFoundError as error:
                logger(logging.ERROR, "File not found")
                raise error
            except ClientError as error:
                logger(logging.ERROR, error)
                raise error

        folder = os.path.dirname(bucket_path)
        self._register_bucket_did(bucket_name, folder)
        return 0

    def _register_bucket_did(self, scope, name):
        logger = self.logger

        logger(logging.DEBUG, "Registering bucket")

        account_scopes = []
        try:
            account_scopes = self.client.list_scopes_for_account(self.client.account)
        except ScopeNotFound:
            pass

        if account_scopes and scope not in account_scopes:
            logger(
                logging.WARNING,
                "Scope {} not found for the account {}.".format(
                    scope, self.client.account
                ),
            )

        dataset_did_str = "%s:%s" % (scope, name)
        try:
            logger(logging.DEBUG, "Trying to create dataset: %s" % dataset_did_str)
            self.client.add_dataset(scope=scope, name=name)
            logger(logging.INFO, "Successfully created dataset %s" % dataset_did_str)
        except DataIdentifierAlreadyExists:
            logger(
                logging.INFO,
                "S3Client dataset did %s already exists - no rule will be created"
                % dataset_did_str,
            )
        else:
            logger(logging.DEBUG, "Skipping dataset registration")

    def bucket_download(self, from_path, to_path):
        """Download a file/folder from an S3 bucket.

        :param from_path: Bucket path, e.g. user.dquijote:/mybucket/file.ext
        :param to_path: Path to the file/folder to download
        :return: 0 if data written successfully, else 1
        """
        logger = self.logger
        bucket_name, bucket_path = from_path.split(":")

        # fn = os.path.basename(to_path)
        try:
            self.s3.download_file(bucket_name, bucket_path, to_path)
            return 0
        except ClientError as error:
            logger(logging.ERROR, error)
            raise error

        # if os.path.isdir(to_path):
