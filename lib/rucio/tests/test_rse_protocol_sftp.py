# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import json
import os
import pysftp
import subprocess

from nose.tools import *

from rucio.rse import rse
from rucio.rse.rseexception import RSEException


class TestRseSFTP():
    def setUp(self):
        """SFTP (RSE/PROTOCOLS): Creating necessary directories and files """
        subprocess.call(["mkdir", "/tmp/rucio"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/local"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/remote"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/1_local_rse_1M.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/2_local_rse_1M.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        # Load local creditentials from file
        credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials['username'] = str(data['cern.lxplus.ch']['username'])
        credentials['password'] = str(data['cern.lxplus.ch']['password'])
        credentials['host'] = 'lxplus.cern.ch'
        lxplus = pysftp.Connection(**credentials)
        lxplus.execute('mkdir ~/rse_test')
        lxplus.execute('dd if=/dev/urandom of=~/rse_test/1_lxplus.raw bs=1024 count=1024')
        lxplus.execute('dd if=/dev/urandom of=~/rse_test/2_lxplus.raw bs=1024 count=1024')
        lxplus.close()
        self.storage = rse.RucioStorageElement(id='cern.lxplus.ch')
        self.storage.connect(credentials)

    def tearDown(self):
        """SFTP (RSE/PROTOCOLS): Removing created directories and files """
        # Load local creditentials from file
        credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials['username'] = str(data['cern.lxplus.ch']['username'])
        credentials['password'] = str(data['cern.lxplus.ch']['password'])
        credentials['host'] = 'lxplus.cern.ch'
        lxplus = pysftp.Connection(**credentials)
        lxplus.execute('rm -rf ~/rse_test')
        lxplus.close()
        self.storage.close()
        os.system('rm -rf /tmp/rucio')

    def test_get_success(self):
        """SFTP (RSE/PROTOCOLS): Requesting file from cern.lxplus """
        self.storage.get(['1_lxplus.raw', '2_lxplus.raw'], '/tmp/rucio/remote')

    def test_get_failure(self):
        """SFTP (RSE/PROTOCOLS): Request none-existing file from given storage """
        try:
            self.storage.get(['not_existing_data.raw'])
        except RSEException as e:
            if e.error_id == 404:
                return
        raise Exception('This should have thrown an error with ID 404')

    def test_put_success(self):
        """SFTP (RSE/PROTOCOLS): Put local file to server """
        self.storage.put(['1_local_rse_1M.raw', '2_local_rse_1M.raw'], '/tmp/rucio/local')

    def test_put_failure(self):
        """SFTP (RSE/PROTOCOLS): Put none-existing local file to server """
        try:
            self.storage.put(['not_existing_data.raw'], '/tmp/rucio/local')
        except RSEException as e:
            if e.error_id == 404:
                return
        raise Exception('This should have thrown an error with ID 404')

    def test_delete_success(self):
        """SFTP (RSE/PROTOCOLS): Delete file from server """
        self.storage.delete(['1_lxplus.raw', '2_lxplus.raw'])

    def test_delete_failure(self):
        """SFTP (RSE/PROTOCOLS): Delete none-existing file from server """
        try:
            self.storage.delete(['not_existing_data.raw'])
        except RSEException as e:
            if e.error_id == 404:
                return
        raise Exception('This should have thrown an error with ID 404')

    def test_exists_success(self):
        """SFTP (RSE/PROTOCOLS): Check if existing file is found by exists """
        assert self.storage.exists('1_lxplus.raw')

    def test_exists_failure(self):
        """SFTP (RSE/PROTOCOLS): Check if none-existing file is not found by exists """
        assert not self.storage.exists('not_existing_data.raw')
