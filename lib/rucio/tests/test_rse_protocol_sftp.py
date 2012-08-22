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

from rucio.common import exception
from rucio.rse import rsemanager


class TestRseSFTP():
    def setUp(self):
        """SFTP (RSE/PROTOCOLS): Creating necessary directories and files """
        subprocess.call(["mkdir", "/tmp/rucio"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/local"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/remote"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/1_rse_local.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/2_rse_local.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/3_rse_local.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/4_rse_local.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        # Load local creditentials from file
        self.credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        self.credentials = data['lxplus.cern.ch']
        lxplus = pysftp.Connection(**self.credentials)
        lxplus.execute('mkdir ~/rse_test')
        files = ['1_rse_remote.raw', '2_rse_remote.raw', '3_rse_remote.raw', '4_rse_remote.raw']
        for f in files:
            lxplus.execute('dd if=/dev/urandom of=~/rse_test/%s bs=1024 count=1024' % f)
        lxplus.close()

    def tearDown(self):
        """SFTP (RSE/PROTOCOLS): Removing created directories and files """
        # Load local creditentials from file
        credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials['username'] = str(data['lxplus.cern.ch']['username'])
        credentials['password'] = str(data['lxplus.cern.ch']['password'])
        credentials['host'] = 'lxplus.cern.ch'
        lxplus = pysftp.Connection(**credentials)
        lxplus.execute('rm -rf ~/rse_test')
        lxplus.close()
        os.system('rm -rf /tmp/rucio')

    def test_get_mgr(self):
        """SFTP (RSE/PROTOCOLS): Requesting files from lxplus.cern.ch using the RSEMgr"""
        gs = True
        status = None
        details = None
        match = False

        mgr = rsemanager.RSEMgr()

        # Files are there cases
        # Bulk
        status, details = mgr.download('lxplus.cern.ch', ['1_rse_remote.raw', '2_rse_remote.raw'], '/tmp/rucio/remote')
        if not status:
            print 'Bulk Mode: Get existing files failed'
            print status, details
            gs = False
        # Single
        try:
            mgr.download('lxplus.cern.ch', '1_rse_remote.raw', '/tmp/rucio/remote')
        except Exception as e:
            print 'Single Mode: Get existing file failed'
            print e
            gs = False

        # Files do not exists cases
        match = False
        # Bulk
        try:
            status, details = mgr.download('lxplus.cern.ch', ['not_existing_data.raw', '1_rse_remote.raw'], '/tmp/rucio/remote')
            if details['1_rse_remote.raw']:
                raise details['not_existing_data.raw']
            else:
                gs = False
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Bulk Mode: Get exsisting and none-existing files failed'
            print status, details
            gs = False
        # Single
        match = False
        try:
            mgr.download('lxplus.cern.ch', 'not_existing_data.raw')
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Get none-existing file failed'
            gs = False
        assert gs

    def test_put_mgr(self):
        """SFTP (RSE/PROTOCOLS): Put local file to server using the RSEMgr"""
        gs = True
        status = None
        details = None
        match = False

        mgr = rsemanager.RSEMgr()

        # Files are there cases
        # Bulk
        status, details = mgr.upload('lxplus.cern.ch', ['1_rse_local.raw', '2_rse_local.raw'], '/tmp/rucio/local')
        if not status:
            print 'Bulk Mode: Upload existing files failed'
            print status, details
            gs = False
        # Single
        try:
            mgr.upload('lxplus.cern.ch', '3_rse_local.raw', '/tmp/rucio/local')
        except Exception as e:
            print 'Single Mode: Upload existing file failed'
            print e
            gs = False

        # Files do not exists cases
        match = False
        # Bulk
        try:
            status, details = mgr.upload('lxplus.cern.ch', ['not_existing_data.raw', '2_rse_local.raw'], '/tmp/rucio/local')
            if details['2_rse_local.raw']:
                raise details['not_existing_data.raw']
            else:
                gs = False
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Mix Mode: Upload  with one missing local file failed'
            print status, details
            gs = False
        # Single
        match = False
        try:
            mgr.upload('lxplus.cern.ch', 'not_existing_data2.raw', '/tmp/rucio/local')
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Upload with missing local file falied'
            gs = False

        # Files already on storage cases
        match = False
        # Bulk
        try:
            status, details = mgr.upload('lxplus.cern.ch', ['2_rse_local.raw', '4_rse_local.raw'], '/tmp/rucio/local')
            if details['4_rse_local.raw']:
                raise details['2_rse_local.raw']
            else:
                gs = False
        except exception.FileReplicaAlreadyExists:
            print 'Bulk Match'
            print status, details
            match = True
        if not match:
            print 'Mix Mode: Upload  where files already on the storage failed.'
            print status, details
            gs = False
        # Single
        match = False
        try:
            mgr.upload('lxplus.cern.ch', '3_rse_local.raw', '/tmp/rucio/local')
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Single Mode: Upload with file already on the storage falied'
            gs = False
        assert gs

    def test_delete_mgr(self):
        """SFTP (RSE/PROTOCOLS): Delete file from server using the RSEMgr"""
        gs = True
        status = None
        details = None
        match = False

        mgr = rsemanager.RSEMgr()

        # Files are there cases
        # Bulk
        status, details = mgr.delete('lxplus.cern.ch', ['1_rse_remote.raw', '2_rse_remote.raw'])
        if not status:
            print 'Bulk Mode: Delete existing files failed'
            print status, details
            gs = False
        # Single
        try:
            mgr.delete('lxplus.cern.ch', '3_rse_remote.raw')
        except Exception as e:
            print 'Single Mode: Delete existing file failed'
            print e
            gs = False

        # Files do not exists cases
        match = False
        # Bulk
        try:
            status, details = mgr.delete('lxplus.cern.ch', ['not_existing_data.raw', '4_rse_remote.raw'])
            if details['4_rse_remote.raw']:
                raise details['not_existing_data.raw']
            else:
                gs = False
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Bulk Mode: Delete existing and none-existing files failed'
            print status, details
            gs = False
        # Single
        match = False
        try:
            mgr.delete('lxplus.cern.ch', 'not_existing_data.raw')
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Delete none-existing file failed'
            gs = False
        assert gs

    def test_exists_mgr(self):
        """SFTP (RSE/PROTOCOLS): Check if existing files are found and none-existing not using the RSEMgr"""
        gs = True
        status = None
        details = None

        mgr = rsemanager.RSEMgr()

        status, details = mgr.exists('lxplus.cern.ch', ['1_rse_remote.raw', '2_rse_remote.raw'])
        if not (details['1_rse_remote.raw'] and details['1_rse_remote.raw']):
            print 'Bulk Mode: Existing files failed'
            print status, details
            gs = False
        status, details = mgr.exists('lxplus.cern.ch', ['1_rse_remote.raw', 'not_existing_data.raw'])
        if not details['1_rse_remote.raw'] or details['not_existing_data.raw']:
            print 'Bulk Mode: Existing and none-existing files failed'
            print status, details
            gs = False
        if not mgr.exists('lxplus.cern.ch', '1_rse_remote.raw'):
            print 'Single Mode: Existing file failed'
            gs = False
        if mgr.exists('lxplus.cern.ch', 'not_existing_data.raw'):
            print 'Single Mode: None-existing file failed'
            gs = False
        assert gs

    def test_rename_mgr(self):
        """SFTP (RSE/PROTOCOLS): Renaming files using the RSEMgr"""
        gs = True
        status = None
        details = None
        match = False

        mgr = rsemanager.RSEMgr()

        # Everything fine
        status, details = mgr.rename('lxplus.cern.ch', {'1_rse_remote.raw': '1_rse_new.raw', '2_rse_remote.raw': '2_rse_new.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_remote.raw, 4_rse_remote.raw
        if not status or not (details['1_rse_remote.raw'] and details['2_rse_remote.raw']):
            print 'Bulk Mode: Existing files failed'
            print status, details
            gs = False
        try:
            mgr.rename('lxplus.cern.ch', {'3_rse_remote.raw': '3_rse_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_remote.raw
        except Exception as e:
            print 'Single Mode: Existing file failed'
            print e
            gs = False

        # File already exists
        match = False
        status, details = mgr.rename('lxplus.cern.ch', {'1_rse_new.raw': '2_rse_new.raw', '2_rse_new.raw': '1_rse_new.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_remote.raw
        if status:
            print 'Bulk Mode: All targets exist failed'
            print status, details
            gs = False
        match = False
        try:
            status, details = mgr.rename('lxplus.cern.ch', {'1_rse_new.raw': '2_rse_new.raw', '4_rse_remote.raw': '4_rse_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_new.raw
            if not status:
                if details['4_rse_remote.raw']:
                    raise details['1_rse_new.raw']
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Bulk Mode: Existing and none-existing targets failed'
            print status, details
            gs = False
        match = False
        try:
            mgr.rename('lxplus.cern.ch', {'3_rse_new.raw': '4_rse_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_new.raw
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Single Mode: Existing target failed'
            gs = False

        # Source not found
        match = False
        status, details = mgr.rename('lxplus.cern.ch', {'1_rse_not_existing.raw': '1_rse_new_not_created.raw', '2_rse_not_existing.raw': '2_rse_new_not_created.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_new.raw
        if status:
            print 'Bulk Mode: Rename none-existing files failed'
            print status, details
            gs = False
        match = False
        try:
            status, details = mgr.rename('lxplus.cern.ch', {'1_rse_not_existing.raw': '1_rse_new_not_created.raw', '2_rse_new.raw': '2_rse_new_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new_new.raw, 3_rse_new.raw, 4_rse_new.raw
            if not status:
                if details['2_rse_new.raw']:
                    raise details['1_rse_not_existing.raw']
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Bulk Mode: Rename existing and none-existing files failed'
            print status, details
            gs = False
        match = False
        try:
            mgr.rename('lxplus.cern.ch', {'1_rse_not_existing.raw': '1_rse_new_not_created.raw'})
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Rename none-existing file failed'
            gs = False
        assert gs

    def test_get(self):
        """SFTP (RSE/PROTOCOLS): Requesting files from lxplus.cern.ch """
        match = False
        gs = True
        status = None
        details = None

        storage = rsemanager.RSE('lxplus.cern.ch')
        storage.connect(self.credentials)
        # Files are there cases
        # Bulk
        status, details = storage.get(['1_rse_remote.raw', '2_rse_remote.raw'], '/tmp/rucio/remote')
        if not status:
            print 'Bulk Mode: Get existing files failed'
            print status, details
            gs = False
        # Single
        try:
            storage.get('1_rse_remote.raw', '/tmp/rucio/remote')
        except Exception as e:
            print 'Single Mode: Get existing file failed'
            print e
            gs = False

        # Files do not exists cases
        match = False
        # Bulk
        try:
            status, details = storage.get(['not_existing_data.raw', '1_rse_remote.raw'], '/tmp/rucio/remote')
            if details['1_rse_remote.raw']:
                raise details['not_existing_data.raw']
            else:
                gs = False
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Bulk Mode: Get exsisting and none-existing files failed'
            print status, details
            gs = False
        # Single
        match = False
        try:
            storage.get('not_existing_data.raw', '/tmp/rucio/remote')
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Get none-existing file failed'
            gs = False
        assert gs

    def test_put(self):
        """SFTP (RSE/PROTOCOLS): Put local file to server """
        match = False
        gs = True
        status = None
        details = None

        storage = rsemanager.RSE('lxplus.cern.ch')
        storage.connect(self.credentials)
        # Files are there cases
        # Bulk
        status, details = storage.put(['1_rse_local.raw', '2_rse_local.raw'], '/tmp/rucio/local')
        if not status:
            print 'Bulk Mode: Upload existing files failed'
            print status, details
            gs = False
        # Single
        try:
            storage.put('3_rse_local.raw', '/tmp/rucio/local')
        except Exception as e:
            print 'Single Mode: Upload existing file failed'
            print e
            gs = False

        # Files do not exists cases
        match = False
        # Bulk
        try:
            status, details = storage.put(['not_existing_data.raw', '2_rse_local.raw'], '/tmp/rucio/local')
            if details['2_rse_local.raw']:
                raise details['not_existing_data.raw']
            else:
                gs = False
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Mix Mode: Upload  with one missing local file failed'
            print status, details
            gs = False
        # Single
        match = False
        try:
            storage.put('not_existing_data2.raw', '/tmp/rucio/local')
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Upload with missing local file falied'
            gs = False

        # Files already on storage cases
        match = False
        # Bulk
        try:
            status, details = storage.put(['2_rse_local.raw', '4_rse_local.raw'], '/tmp/rucio/local')
            if details['4_rse_local.raw']:
                raise details['2_rse_local.raw']
            else:
                gs = False
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Mix Mode: Upload  where files already on the storage failed.'
            print status, details
            gs = False
        # Single
        match = False
        try:
            storage.put('3_rse_local.raw', '/tmp/rucio/local')
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Single Mode: Upload with file already on the storage falied'
            gs = False

        assert gs

    def test_delete(self):
        """SFTP (RSE/PROTOCOLS): Delete file from server """
        match = False
        gs = True
        status = None
        details = None

        storage = rsemanager.RSE('lxplus.cern.ch')
        storage.connect(self.credentials)
        # Files are there cases
        # Bulk
        status, details = storage.delete(['1_rse_remote.raw', '2_rse_remote.raw'])
        if not status:
            print 'Bulk Mode: Delete existing files failed'
            print status, details
            gs = False
        # Single
        try:
            storage.delete('3_rse_remote.raw')
        except Exception as e:
            print 'Single Mode: Delete existing file failed'
            print e
            gs = False

        # Files do not exists cases
        match = False
        # Bulk
        try:
            status, details = storage.delete(['not_existing_data.raw', '4_rse_remote.raw'])
            if details['4_rse_remote.raw']:
                raise details['not_existing_data.raw']
            else:
                gs = False
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Bulk Mode: Delete existing and none-existing files failed'
            print status, details
            gs = False
        # Single
        match = False
        try:
            storage.delete('not_existing_data.raw')
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Delete none-existing file failed'
            gs = False
        assert gs

    def test_exists(self):
        """SFTP (RSE/PROTOCOLS): Check if existing files are found and none-existing not """
        gs = True
        status = None
        details = None

        storage = rsemanager.RSE('lxplus.cern.ch')
        storage.connect(self.credentials)
        status, details = storage.exists(['1_rse_remote.raw', '2_rse_remote.raw'])
        if not (details['1_rse_remote.raw'] and details['1_rse_remote.raw']):
            print 'Bulk Mode: Existing files failed'
            print status, details
            gs = False
        status, details = storage.exists(['1_rse_remote.raw', 'not_existing_data.raw'])
        if not details['1_rse_remote.raw'] or details['not_existing_data.raw']:
            print 'Bulk Mode: Existing and none-existing files failed'
            print status, details
            gs = False
        if not storage.exists('1_rse_remote.raw'):
            print 'Single Mode: Existing file failed'
            gs = False
        if storage.exists('not_existing_data.raw'):
            print 'Single Mode: None-existing file failed'
            gs = False
        assert gs

    def test_rename(self):
        """SFTP (RSE/PROTOCOLS): Renaming files """
        match = False
        gs = True
        status = None
        details = None

        storage = rsemanager.RSE('lxplus.cern.ch')
        storage.connect(self.credentials)
        # Everything fine
        status, details = storage.rename({'1_rse_remote.raw': '1_rse_new.raw', '2_rse_remote.raw': '2_rse_new.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_remote.raw, 4_rse_remote.raw
        if not status or not (details['1_rse_remote.raw'] and details['2_rse_remote.raw']):
            print 'Bulk Mode: Existing files failed'
            print status, details
            gs = False
        try:
            storage.rename({'3_rse_remote.raw': '3_rse_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_remote.raw
        except Exception as e:
            print 'Single Mode: Existing file failed'
            print e
            gs = False

        # File already exists
        match = False
        status, details = storage.rename({'1_rse_new.raw': '2_rse_new.raw', '2_rse_new.raw': '1_rse_new.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_remote.raw
        if status:
            print 'Bulk Mode: All targets exist failed'
            print status, details
            gs = False
        match = False
        try:
            status, details = storage.rename({'1_rse_new.raw': '2_rse_new.raw', '4_rse_remote.raw': '4_rse_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_new.raw
            if not status:
                if details['4_rse_remote.raw']:
                    raise details['1_rse_new.raw']
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Bulk Mode: Existing and none-existing targets failed'
            print status, details
            gs = False
        match = False
        try:
            storage.rename({'3_rse_new.raw': '4_rse_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_new.raw
        except exception.FileReplicaAlreadyExists:
            match = True
        if not match:
            print 'Single Mode: Existing target failed'
            gs = False

        # Source not found
        match = False
        status, details = storage.rename({'1_rse_not_existing.raw': '1_rse_new_not_created.raw', '2_rse_not_existing.raw': '2_rse_new_not_created.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_new.raw, 4_rse_new.raw
        if status:
            print 'Bulk Mode: Rename none-existing files failed'
            print status, details
            gs = False
        match = False
        try:
            status, details = storage.rename({'1_rse_not_existing.raw': '1_rse_new_not_created.raw', '2_rse_new.raw': '2_rse_new_new.raw'})
            # Files after renaming: 1_rse_new.raw, 2_rse_new_new.raw, 3_rse_new.raw, 4_rse_new.raw
            if not status:
                if details['2_rse_new.raw']:
                    raise details['1_rse_not_existing.raw']
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Bulk Mode: Rename existing and none-existing files failed'
            print status, details
            gs = False
        match = False
        try:
            storage.rename({'1_rse_not_existing.raw': '1_rse_new_not_created.raw'})
        except exception.SourceNotFound:
            match = True
        if not match:
            print 'Single Mode: Rename none-existing file failed'
            gs = False
        assert gs
