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

import itertools
import os
import os.path
import shutil
import tempfile
from uuid import uuid4 as uuid

import pytest

from rucio.common import exception
from rucio.common.checksum import adler32, md5
from rucio.rse import rsemanager as mgr
from rucio.tests.common import load_test_conf_file, skip_rse_tests_with_accounts


@skip_rse_tests_with_accounts
class MgrTestCases:
    files_local = [
        "1_rse_local_put.raw",
        "2_rse_local_put.raw",
        "3_rse_local_put.raw",
        "4_rse_local_put.raw",
    ]
    files_local_and_remote = [
        "1_rse_local_and_remote_put.raw",
        "2_rse_local_and_remote_put.raw",
    ]
    files_remote = [
        "1_rse_remote_get.raw",
        "2_rse_remote_get.raw",
        "3_rse_remote_get.raw",
        "4_rse_remote_get.raw",
        "1_rse_remote_delete.raw",
        "2_rse_remote_delete.raw",
        "3_rse_remote_delete.raw",
        "4_rse_remote_delete.raw",
        "1_rse_remote_exists.raw",
        "2_rse_remote_exists.raw",
        "1_rse_remote_rename.raw",
        "2_rse_remote_rename.raw",
        "3_rse_remote_rename.raw",
        "4_rse_remote_rename.raw",
        "5_rse_remote_rename.raw",
        "6_rse_remote_rename.raw",
        "7_rse_remote_rename.raw",
        "8_rse_remote_rename.raw",
        "9_rse_remote_rename.raw",
        "10_rse_remote_rename.raw",
        "11_rse_remote_rename.raw",
        "12_rse_remote_rename.raw",
        "1_rse_remote_change_scope.raw",
        "2_rse_remote_change_scope.raw",
    ]

    def init(self, tmpdir, rse_settings, user, vo, impl=None):
        self.tmpdir = tmpdir
        self.rse_settings = rse_settings
        self.user = user
        self.vo = vo
        self.impl = None
        if impl:
            if len(impl.split(".")) == 1:
                self.impl = "rucio.rse.protocols." + impl + ".Default"
            else:
                self.impl = "rucio.rse.protocols." + impl

    @classmethod
    def setup_common_test_env(cls, rse_name, vo, tmp_path_factory):
        rse_settings = mgr.get_rse_info(rse=rse_name, vo=vo)
        tmpdir = tmp_path_factory.mktemp(cls.__name__)
        user = uuid()
        try:
            data = load_test_conf_file("rse-accounts.cfg.template")
            rse_settings["credentials"] = data[rse_name]
        except KeyError:
            print("No credentials found for this RSE.")
            pass

        # Generate local files
        with open("%s/data.raw" % tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write(b'\0')
        for f in itertools.chain(cls.files_local, cls.files_local_and_remote):
            shutil.copy('%s/data.raw' % tmpdir, '%s/%s' % (tmpdir, f))

        return rse_settings, str(tmpdir), user

    def setup_scheme(self, scheme):
        """(RSE/PROTOCOLS):  Make mgr to select this scheme first."""
        for protocol in self.rse_settings['protocols']:
            if scheme and protocol['scheme'] != scheme:
                self.rse_settings['protocols'].remove(protocol)

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """(RSE/PROTOCOLS): Put multiple files to storage (Success)"""

        if self.rse_settings['protocols'][0]['hostname'] == 'ssh1':
            result = mgr.upload(self.rse_settings, [{'name': '1_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                                     'md5': md5(str(self.tmpdir) + '/1_rse_local_put.raw'),
                                                     'filesize': os.stat('%s/1_rse_local_put.raw' % self.tmpdir)[
                                                         os.path.stat.ST_SIZE]},
                                                    {'name': '2_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                                     'md5': md5(str(self.tmpdir) + '/2_rse_local_put.raw'),
                                                     'filesize': os.stat('%s/2_rse_local_put.raw' % self.tmpdir)[
                                                         os.path.stat.ST_SIZE]}], source_dir=self.tmpdir, vo=self.vo,
                                impl=self.impl)
        else:
            result = mgr.upload(self.rse_settings, [{'name': '1_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                                     'adler32': adler32('%s/1_rse_local_put.raw' % self.tmpdir),
                                                     'filesize': os.stat('%s/1_rse_local_put.raw' % self.tmpdir)[
                                                         os.path.stat.ST_SIZE]},
                                                    {'name': '2_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                                     'adler32': adler32('%s/2_rse_local_put.raw' % self.tmpdir),
                                                     'filesize': os.stat('%s/2_rse_local_put.raw' % self.tmpdir)[
                                                         os.path.stat.ST_SIZE]}], source_dir=self.tmpdir, vo=self.vo)

        status = result[0]
        details = result[1]
        assert status
        assert details['user.%s:1_rse_local_put.raw' % self.user] is True
        assert details['user.%s:2_rse_local_put.raw' % self.user] is True

    def test_put_mgr_ok_single(self):
        """(RSE/PROTOCOLS): Put a single file to storage (Success)"""
        if self.rse_settings['protocols'][0]['hostname'] == 'ssh1':
            mgr.upload(self.rse_settings, {'name': '3_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                           'md5': md5('%s/3_rse_local_put.raw' % self.tmpdir), 'filesize': os.stat('%s/3_rse_local_put.raw' % self.tmpdir)[os.path.stat.ST_SIZE]}, source_dir=self.tmpdir, vo=self.vo, impl=self.impl)
        else:
            mgr.upload(self.rse_settings, {'name': '3_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                           'adler32': adler32('%s/3_rse_local_put.raw' % self.tmpdir), 'filesize': os.stat('%s/3_rse_local_put.raw' % self.tmpdir)[os.path.stat.ST_SIZE]}, source_dir=self.tmpdir, vo=self.vo)

    def test_put_mgr_source_not_found_multi(self):
        """(RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        result = mgr.upload(self.rse_settings, [{'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user,
                                                'adler32': 'some_random_stuff', 'filesize': 4711},
                                                {'name': '4_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                                 'adler32': adler32('%s/4_rse_local_put.raw' % self.tmpdir), 'filesize': os.stat('%s/4_rse_local_put.raw' % self.tmpdir)[os.path.stat.ST_SIZE]}], source_dir=self.tmpdir, vo=self.vo, impl=self.impl)
        details = result[1]
        assert details['user.%s:4_rse_local_put.raw' % self.user]
        assert isinstance(details['user.%s:not_existing_data.raw' % self.user], exception.SourceNotFound)

    def test_put_mgr_source_not_found_single(self):
        """(RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            mgr.upload(self.rse_settings, {'name': 'not_existing_data2.raw', 'scope': 'user.%s' % self.user, 'adler32': 'random_stuff', 'filesize': 0}, source_dir=self.tmpdir, vo=self.vo, impl=self.impl)

    def test_put_mgr_file_replica_already_exists_multi(self):
        """(RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        result = mgr.upload(self.rse_settings, [{'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'adler32': "bla-bla", 'filesize': 4711},
                                                {'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'adler32': "bla-bla", 'filesize': 4711}], source_dir=self.tmpdir, vo=self.vo, impl=self.impl)
        details = result[1]
        assert isinstance(details['user.%s:1_rse_remote_get.raw' % self.user], exception.FileReplicaAlreadyExists)
        assert isinstance(details['user.%s:2_rse_remote_get.raw' % self.user], exception.FileReplicaAlreadyExists)

    def test_put_mgr_file_replica_already_exists_single(self):
        """(RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            mgr.upload(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'adler32': 'bla-bla', 'filesize': 4711}, source_dir=self.tmpdir, vo=self.vo, impl=self.impl)

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """(RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        result = mgr.delete(self.rse_settings, [{'name': '1_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}, {'name': '2_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}], impl=self.impl)
        status = result[0]
        details = result[1]
        assert status
        assert details['user.%s:1_rse_remote_delete.raw' % self.user] is True or isinstance(details['user.%s:1_rse_remote_delete.raw' % self.user], NotImplementedError)
        assert details['user.%s:2_rse_remote_delete.raw' % self.user] is True or isinstance(details['user.%s:2_rse_remote_delete.raw' % self.user], NotImplementedError)

    def test_delete_mgr_ok_single(self):
        """(RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        mgr.delete(self.rse_settings, {'name': '3_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}, impl=self.impl)

    def test_delete_mgr_ok_dir(self):
        """(RSE/PROTOCOLS): Delete a directory from storage (Success)"""
        mgr.delete(self.rse_settings, {'path': 'user/%s' % self.user, 'name': 'user.%s' % self.user, 'scope': 'user.%s' % self.user}, impl=self.impl)

    def test_delete_mgr_source_not_found_multi(self):
        """(RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        status, details = mgr.delete(self.rse_settings, [{'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}, {'name': '4_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}], impl=self.impl)
        assert details['user.%s:4_rse_remote_delete.raw' % self.user] is True
        assert isinstance(details['user.%s:not_existing_data.raw' % self.user], exception.SourceNotFound)

    def test_delete_mgr_source_not_found_single(self):
        """(RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            mgr.delete(self.rse_settings, {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}, impl=self.impl)

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """(RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        pfn_a = list(mgr.lfns2pfns(self.rse_settings, {'name': '3_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b = list(mgr.lfns2pfns(self.rse_settings, {'name': '4_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        status, details = mgr.exists(self.rse_settings, [{'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user},
                                                         {'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user},
                                                         {'name': pfn_a},
                                                         {'name': pfn_b}], impl=self.impl, vo=self.vo)
        assert status
        assert details['user.%s:1_rse_remote_get.raw' % self.user] is True
        assert details['user.%s:2_rse_remote_get.raw' % self.user] is True
        assert details[pfn_a] is True
        assert details[pfn_b] is True

    def test_exists_mgr_ok_single_lfn(self):
        """(RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        mgr.exists(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl, vo=self.vo)

    def test_exists_mgr_ok_single_pfn(self):
        """(RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        mgr.exists(self.rse_settings, {'name': pfn}, impl=self.impl, vo=self.vo)

    def test_exists_mgr_false_multi(self):
        """(RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        pfn_a = list(mgr.lfns2pfns(self.rse_settings, {'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        status, details = mgr.exists(self.rse_settings, [{'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user},
                                                         {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user},
                                                         {'name': pfn_a},
                                                         {'name': pfn_b}], impl=self.impl, vo=self.vo)
        assert not status
        assert details['user.%s:1_rse_remote_get.raw' % self.user] is True
        assert details['user.%s:not_existing_data.raw' % self.user] is False
        assert details[pfn_a] is True
        assert details[pfn_b] is False

    def test_exists_mgr_false_single_lfn(self):
        """(RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        assert not mgr.exists(self.rse_settings, {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}, impl=self.impl, vo=self.vo)

    def test_exists_mgr_false_single_pfn(self):
        """(RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        assert not mgr.exists(self.rse_settings, {'name': pfn}, impl=self.impl, vo=self.vo)

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """(RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        protocol = mgr.create_protocol(self.rse_settings, 'write', impl=self.impl)
        pfn_a = list(protocol.lfns2pfns({'name': '7_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}).values())[0]
        pfn_a_new = list(protocol.lfns2pfns({'name': '7_rse_new_rename.raw', 'scope': 'user.%s' % self.user}).values())[0]
        pfn_b = list(protocol.lfns2pfns({'name': '8_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}).values())[0]
        pfn_b_new = list(protocol.lfns2pfns({'name': '8_rse_new_rename.raw', 'scope': 'user.%s' % self.user}).values())[0]
        status, details = mgr.rename(self.rse_settings, [{'name': '1_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_remote_renamed.raw'},
                                                         {'name': '2_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '2_rse_remote_renamed.raw'},
                                                         {'name': pfn_a, 'new_name': pfn_a_new},
                                                         {'name': pfn_b, 'new_name': pfn_b_new}], impl=self.impl)
        assert status
        assert details['user.%s:1_rse_remote_rename.raw' % self.user]
        assert details['user.%s:2_rse_remote_rename.raw' % self.user]
        assert details[pfn_a]
        assert details[pfn_b]

    def test_rename_mgr_ok_single_lfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        mgr.rename(self.rse_settings, {'name': '3_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '3_rse_remote_renamed.raw', 'new_scope': 'user.%s' % self.user}, impl=self.impl)

    def test_rename_mgr_ok_single_pfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '9_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '9_rse_new.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_rename_mgr_file_replica_already_exists_multi(self):
        """(RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        pfn_a = list(mgr.lfns2pfns(self.rse_settings, {'name': '10_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_a_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b = list(mgr.lfns2pfns(self.rse_settings, {'name': '11_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '11_rse_new_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        status, details = mgr.rename(self.rse_settings, [{'name': '4_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_remote_get.raw', 'new_scope': 'user.%s' % self.user},
                                                         {'name': '5_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '5_rse_new.raw'},
                                                         {'name': pfn_a, 'new_name': pfn_a_new},
                                                         {'name': pfn_b, 'new_name': pfn_b_new}], impl=self.impl)
        assert not status
        assert isinstance(details[pfn_a], exception.FileReplicaAlreadyExists)
        assert isinstance(details['user.%s:4_rse_remote_rename.raw' % self.user], exception.FileReplicaAlreadyExists)
        assert details['user.%s:5_rse_remote_rename.raw' % self.user]
        assert details[pfn_b]

    def test_rename_mgr_file_replica_already_exists_single_lfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using LFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            mgr.rename(self.rse_settings, {'name': '6_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_remote_get.raw', 'new_scope': 'user.%s' % self.user}, impl=self.impl)

    def test_rename_mgr_file_replica_already_exists_single_pfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '12_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        with pytest.raises(exception.FileReplicaAlreadyExists):
            mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_rename_mgr_source_not_found_multi(self):
        """(RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        pfn_a = list(mgr.lfns2pfns(self.rse_settings, {'name': '12_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_created.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        status, details = mgr.rename(self.rse_settings, [{'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_new_not_created.raw'},
                                                         {'name': pfn_a, 'new_name': pfn_b}], impl=self.impl)
        assert not status
        assert isinstance(details['user.%s:1_rse_not_existing.raw' % self.user], exception.SourceNotFound)
        assert isinstance(details[pfn_a], exception.SourceNotFound)

    def test_rename_mgr_source_not_found_single_lfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            mgr.rename(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_new_not_created.raw'}, impl=self.impl)

    def test_rename_mgr_source_not_found_single_pfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_new_not_created.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        with pytest.raises(exception.SourceNotFound):
            mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_change_scope_mgr_ok_single_lfn(self):
        """(RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        mgr.rename(self.rse_settings, {'name': '1_rse_remote_change_scope.raw', 'scope': 'user.%s' % self.user, 'new_scope': 'group.%s' % self.user}, impl=self.impl)

    def test_change_scope_mgr_ok_single_pfn(self):
        """(RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '2_rse_remote_change_scope.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '2_rse_remote_change_scope.raw', 'scope': 'group.%s' % self.user}, impl=self.impl).values())[0]
        mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_download_protocol_ok_single_pfn(self):
        """(RSE/PROTOCOLS): Check a single file download using PFN (Success)"""
        filename = '1_rse_remote_get.raw'
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': filename, 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        protocol = mgr.create_protocol(self.rse_settings, 'write', impl=self.impl)
        protocol.connect()
        with tempfile.TemporaryDirectory() as tmpdirname:
            protocol.get(pfn, dest='%s/%s' % (tmpdirname, filename), transfer_timeout=None)
            assert filename in os.listdir(tmpdirname)
            assert os.path.isfile('%s/%s' % (tmpdirname, filename))
            size = os.stat('%s/%s' % (tmpdirname, filename)).st_size
            assert size == 1048576

    def test_download_protocol_ok_single_pfn_timeout(self):
        """(RSE/PROTOCOLS): Check a single file download using PFN and timeout parameter (Success)"""
        filename = '1_rse_remote_get.raw'
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': filename, 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        protocol = mgr.create_protocol(self.rse_settings, 'write', impl=self.impl)
        protocol.connect()
        with tempfile.TemporaryDirectory() as tmpdirname:
            protocol.get(pfn, dest='%s/%s' % (tmpdirname, filename), transfer_timeout='10')
            assert filename in os.listdir(tmpdirname)
            assert os.path.isfile('%s/%s' % (tmpdirname, filename))
            size = os.stat('%s/%s' % (tmpdirname, filename)).st_size
            assert size == 1048576
