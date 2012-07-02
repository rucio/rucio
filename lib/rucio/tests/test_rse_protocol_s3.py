# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import re
import json
import os
import subprocess

from S3.Exceptions import S3Error

from rucio.rse import rse
from rucio.rse.rseexception import RSEException


class TestRseSFTP():
    def setUp(self):
        """S3 (RSE/PROTOCOLS): Creating necessary directories and files """
        subprocess.call(["mkdir", "/tmp/rucio"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/local"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/remote"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/1_local_rse_1M.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/2_local_rse_1M.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        # Load local creditentials from file
        credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials = data['swift.cern.ch']
        self.storage = rse.RucioStorageElement(id='swift.cern.ch')
        self.storage.connect(credentials)
        # Create test files on storage
        uri = [self.storage.lfn2uri('1_swift_rse.raw'), self.storage.lfn2uri('2_swift_rse.raw')]
        fnull = open(os.devnull, 'w')
        try:
            subprocess.call(["s3cmd", "mb", re.search('s3://[^/]+/', uri[0]).group(0)], stdout=fnull, stderr=fnull)
            subprocess.call(["s3cmd", "mb", re.search('s3://[^/]+/', uri[1]).group(0)], stdout=fnull, stderr=fnull)
        except S3Error:
            pass
        subprocess.call(["s3cmd", "put", "/tmp/rucio/local/1_local_rse_1M.raw", uri[0]], stdout=fnull, stderr=fnull)
        subprocess.call(["s3cmd", "put", "/tmp/rucio/local/2_local_rse_1M.raw", uri[1]], stdout=fnull, stderr=fnull)
        fnull.close()

    def tearDown(self):
        """S3 (RSE/PROTOCOLS): Removing created directories and files """
        # Remove test files from storage
        files = ['1_swift_rse.raw', '2_swift_rse.raw', '1_local_rse_1M.raw', '2_local_rse_1M.raw']
        fnull = open(os.devnull, 'w')
        for f in files:
            subprocess.call(["s3cmd", "del", self.storage.lfn2uri(f), "--no-progress"], stdout=fnull, stderr=fnull)
        fnull.close()
        self.storage.close()
        os.system('rm -rf /tmp/rucio')

    def test_get_success(self):
        """S3 (RSE/PROTOCOLS): Requesting file from swift.cern.ch """
        self.storage.get(['1_swift_rse.raw', '2_swift_rse.raw'], '/tmp/rucio/remote')

    def test_get_failure(self):
        """S3 (RSE/PROTOCOLS): Request none-existing file from given storage """
        try:
            self.storage.get(['not_existing_data.raw'])
        except RSEException as e:
            if e.error_id == 404:
                return
        raise Exception('This should have thrown an error with ID 404')

    def test_put_success(self):
        """S3 (RSE/PROTOCOLS): Put local file to server """
        self.storage.put(['1_local_rse_1M.raw', '2_local_rse_1M.raw'], '/tmp/rucio/local')

    def test_put_failure(self):
        """S3 (RSE/PROTOCOLS): Put none-existing local file to server """
        try:
            self.storage.put(['not_existing_data.raw'], '/tmp/rucio/local')
        except RSEException as e:
            if e.error_id == 404:
                return
        raise Exception('This should have thrown an error with ID 404')

    def test_delete_success(self):
        """S3 (RSE/PROTOCOLS): Delete file from server """
        self.storage.delete(['1_swift_rse.raw', '2_swift_rse.raw'])

    def test_delete_failure(self):
        """S3 (RSE/PROTOCOLS): Delete none-existing file from server """
        try:
            self.storage.delete(['not_existing_data.raw'])
        except RSEException as e:
            if e.error_id == 404:
                return
        raise Exception('This should have thrown an error with ID 404')

    def test_exists_success(self):
        """S3 (RSE/PROTOCOLS): Check if existing file is found by exists """
        assert self.storage.exists('1_swift_rse.raw')

    def test_exists_failure(self):
        """S3 (RSE/PROTOCOLS): Check if none-existing file is not found by exists """
        assert not self.storage.exists('not_existing_data.raw')
