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

import os
import os.path
import tempfile

from rucio.common.utils import adler32, md5
from rucio.rse import rsemanager as mgr
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file


@skip_rse_tests_with_accounts
class MgrTestCases:
    files_local = ["1_rse_local_put.raw", "2_rse_local_put.raw", "3_rse_local_put.raw", "4_rse_local_put.raw"]
    files_local_and_remote = ['1_rse_local_and_remote_put.raw', '2_rse_local_and_remote_put.raw']
    files_remote = ['1_rse_remote_get.raw', '2_rse_remote_get.raw', '3_rse_remote_get.raw', '4_rse_remote_get.raw',
                    '1_rse_remote_delete.raw', '2_rse_remote_delete.raw', '3_rse_remote_delete.raw', '4_rse_remote_delete.raw',
                    '1_rse_remote_exists.raw', '2_rse_remote_exists.raw',
                    '1_rse_remote_rename.raw', '2_rse_remote_rename.raw', '3_rse_remote_rename.raw', '4_rse_remote_rename.raw', '5_rse_remote_rename.raw', '6_rse_remote_rename.raw',
                    '7_rse_remote_rename.raw', '8_rse_remote_rename.raw', '9_rse_remote_rename.raw', '10_rse_remote_rename.raw', '11_rse_remote_rename.raw', '12_rse_remote_rename.raw',
                    '1_rse_remote_change_scope.raw',
                    '2_rse_remote_change_scope.raw']

    def __init__(self, tmpdir, rse_tag, user, static_file, vo='def', impl=None):
        self.rse_settings = mgr.get_rse_info(rse=rse_tag, vo=vo)
        try:
            data = load_test_conf_file('rse-accounts.cfg.template')
            self.rse_settings['credentials'] = data[rse_tag]
        except KeyError:
            print('No credentials found for this RSE.')
            pass
        self.tmpdir = tmpdir
        self.gettmpdir = tempfile.mkdtemp()
        self.user = user
        self.static_file = static_file
        self.impl = None
        if impl and len(self.rse_settings['protocols']) > 0:
            if len(impl.split('.')) == 1:
                self.impl = 'rucio.rse.protocols.' + impl + '.Default'
            else:
                self.impl = 'rucio.rse.protocols.' + impl
        self.vo = vo

    def setup_scheme(self, scheme):
        """(RSE/PROTOCOLS):  Make mgr to select this scheme first."""
        for protocol in self.rse_settings['protocols']:
            if scheme and protocol['scheme'] != scheme:
                self.rse_settings['protocols'].remove(protocol)

    # Mgr-Tests: GET
    # These tests will fail as rsemanager.download has been removed. Commenting out to avoid syntax errors.
    # def test_multi_get_mgr_ok(self):
    #     """(RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
    #     pfn_b = mgr.lfns2pfns(self.rse_settings, {'name': '4_rse_remote_get.raw', 'scope': 'user.%s' % self.user}).values()[0]
    #     status, details = mgr.download(self.rse_settings, [{'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user},
    #                                                        {'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user},
    #                                                        {'name': '3_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'pfn': self.static_file},
    #                                                        {'name': '4_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'pfn': pfn_b}],
    #                                    self.gettmpdir)
    #     if not (status and details['user.%s:1_rse_remote_get.raw' % self.user] and details['user.%s:2_rse_remote_get.raw' % self.user] and details['user.%s:3_rse_remote_get.raw' % self.user] and details['user.%s:4_rse_remote_get.raw' % self.user]):
    #         raise Exception('Return not as expected: %s, %s' % (status, details))

    # def test_get_mgr_ok_single_lfn(self):
    #     """(RSE/PROTOCOLS): Get a single file from storage provding the LFN (Success)"""
    #     mgr.download(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, self.gettmpdir)

    # def test_get_mgr_ok_single_pfn(self):
    #     """(RSE/PROTOCOLS): Get a single file from storage providing the PFN (Success)"""
    #     mgr.download(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'pfn': self.static_file}, self.gettmpdir)

    # def test_get_mgr_SourceNotFound_multi(self):
    #     """(RSE/PROTOCOLS): Get multiple files from storage providing LFNs  and PFNs (SourceNotFound)"""
    #     protocol = mgr.create_protocol(self.rse_settings, 'read')
    #     pfn_a = protocol.lfns2pfns({'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user}).values()[0]
    #     pfn_b = protocol.lfns2pfns({'name': '2_rse_remote_get_not_existing.raw', 'scope': 'user.%s' % self.user}).values()[0]
    #     status, details = mgr.download(self.rse_settings, [{'name': '1_not_existing_data.raw', 'scope': 'user.%s' % self.user},
    #                                                        {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user},
    #                                                        {'name': '2_not_existing_data.raw', 'scope': 'user.%s' % self.user, 'pfn': pfn_b},
    #                                                        {'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'pfn': pfn_a}], self.gettmpdir)
    #     if details['user.%s:1_rse_remote_get.raw' % self.user] and details['user.%s:2_rse_remote_get.raw' % self.user]:
    #         if details['user.%s:1_not_existing_data.raw' % self.user].__class__.__name__ == 'SourceNotFound' and details['user.%s:2_not_existing_data.raw' % self.user].__class__.__name__ == 'SourceNotFound':
    #             raise details['user.%s:1_not_existing_data.raw' % self.user]
    #         else:
    #             raise Exception('Return not as expected: %s, %s' % (status, details))
    #     else:
    #         raise Exception('Return not as expected: %s, %s' % (status, details))

    # def test_get_mgr_SourceNotFound_single_lfn(self):
    #     """(RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNot Found)"""
    #     mgr.download(self.rse_settings, {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}, self.gettmpdir)

    # def test_get_mgr_SourceNotFound_single_pfn(self):
    #     """(RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotF ound)"""
    #     pfn = mgr.lfns2pfns(self.rse_settings, {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}).values()[0]
    #     mgr.download(self.rse_settings, {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user, 'pfn': pfn}, self.gettmpdir)

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
        if not (status and details['user.%s:1_rse_local_put.raw' % self.user] and details['user.%s:2_rse_local_put.raw' % self.user]):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_ok_single(self):
        """(RSE/PROTOCOLS): Put a single file to storage (Success)"""
        if self.rse_settings['protocols'][0]['hostname'] == 'ssh1':
            mgr.upload(self.rse_settings, {'name': '3_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                           'md5': md5('%s/3_rse_local_put.raw' % self.tmpdir), 'filesize': os.stat('%s/3_rse_local_put.raw' % self.tmpdir)[os.path.stat.ST_SIZE]}, source_dir=self.tmpdir, vo=self.vo, impl=self.impl)
        else:
            mgr.upload(self.rse_settings, {'name': '3_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                           'adler32': adler32('%s/3_rse_local_put.raw' % self.tmpdir), 'filesize': os.stat('%s/3_rse_local_put.raw' % self.tmpdir)[os.path.stat.ST_SIZE]}, source_dir=self.tmpdir, vo=self.vo)

    def test_put_mgr_SourceNotFound_multi(self):
        """(RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        result = mgr.upload(self.rse_settings, [{'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user,
                                                'adler32': 'some_random_stuff', 'filesize': 4711},
                                                {'name': '4_rse_local_put.raw', 'scope': 'user.%s' % self.user,
                                                 'adler32': adler32('%s/4_rse_local_put.raw' % self.tmpdir), 'filesize': os.stat('%s/4_rse_local_put.raw' % self.tmpdir)[os.path.stat.ST_SIZE]}], source_dir=self.tmpdir, vo=self.vo, impl=self.impl)
        status = result[0]
        details = result[1]
        if details['user.%s:4_rse_local_put.raw' % self.user]:
            raise details['user.%s:not_existing_data.raw' % self.user]
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_SourceNotFound_single(self):
        """(RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        mgr.upload(self.rse_settings, {'name': 'not_existing_data2.raw', 'scope': 'user.%s' % self.user, 'adler32': 'random_stuff', 'filesize': 0}, source_dir=self.tmpdir, vo=self.vo, impl=self.impl)

    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """(RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        result = mgr.upload(self.rse_settings, [{'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'adler32': "bla-bla", 'filesize': 4711},
                                                {'name': '2_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'adler32': "bla-bla", 'filesize': 4711}], source_dir=self.tmpdir, vo=self.vo, impl=self.impl)
        status = result[0]
        details = result[1]
        if details['user.%s:1_rse_remote_get.raw' % self.user]:
            raise details['user.%s:2_rse_remote_get.raw' % self.user]
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """(RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        mgr.upload(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user, 'adler32': 'bla-bla', 'filesize': 4711}, source_dir=self.tmpdir, vo=self.vo, impl=self.impl)

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """(RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        result = mgr.delete(self.rse_settings, [{'name': '1_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}, {'name': '2_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}], impl=self.impl)
        status = result[0]
        details = result[1]
        if not (status and details['user.%s:1_rse_remote_delete.raw' % self.user] and details['user.%s:2_rse_remote_delete.raw' % self.user]):
            if isinstance(details['user.%s:1_rse_remote_delete.raw' % self.user], NotImplementedError) and isinstance(details['user.%s:2_rse_remote_delete.raw' % self.user], NotImplementedError):
                pass
            else:
                raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_delete_mgr_ok_single(self):
        """(RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        mgr.delete(self.rse_settings, {'name': '3_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}, impl=self.impl)

    def test_delete_mgr_ok_dir(self):
        """(RSE/PROTOCOLS): Delete a directory from storage (Success)"""
        mgr.delete(self.rse_settings, {'path': 'user/%s' % self.user, 'name': 'user.%s' % self.user, 'scope': 'user.%s' % self.user}, impl=self.impl)

    def test_delete_mgr_SourceNotFound_multi(self):
        """(RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        status, details = mgr.delete(self.rse_settings, [{'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}, {'name': '4_rse_remote_delete.raw', 'scope': 'user.%s' % self.user}], impl=self.impl)
        if details['user.%s:4_rse_remote_delete.raw' % self.user]:
            raise details['user.%s:not_existing_data.raw' % self.user]
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_delete_mgr_SourceNotFound_single(self):
        """(RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
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
        if not (status and details['user.%s:1_rse_remote_get.raw' % self.user] and details['user.%s:2_rse_remote_get.raw' % self.user] and details[pfn_a] and details[pfn_b]):
            raise Exception('Return not as expected: %s, %s' % (status, details))

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
        if status or not details['user.%s:1_rse_remote_get.raw' % self.user] or details['user.%s:not_existing_data.raw' % self.user] or not details[pfn_a] or details[pfn_b]:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_mgr_false_single_lfn(self):
        """(RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        not mgr.exists(self.rse_settings, {'name': 'not_existing_data.raw', 'scope': 'user.%s' % self.user}, impl=self.impl, vo=self.vo)

    def test_exists_mgr_false_single_pfn(self):
        """(RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        not mgr.exists(self.rse_settings, {'name': pfn}, impl=self.impl, vo=self.vo)

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
        if not status or not (details['user.%s:1_rse_remote_rename.raw' % self.user] and details['user.%s:2_rse_remote_rename.raw' % self.user] and details[pfn_a] and details[pfn_b]):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_ok_single_lfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        mgr.rename(self.rse_settings, {'name': '3_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '3_rse_remote_renamed.raw', 'new_scope': 'user.%s' % self.user}, impl=self.impl)

    def test_rename_mgr_ok_single_pfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '9_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '9_rse_new.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """(RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        pfn_a = list(mgr.lfns2pfns(self.rse_settings, {'name': '10_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_a_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b = list(mgr.lfns2pfns(self.rse_settings, {'name': '11_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '11_rse_new_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        status, details = mgr.rename(self.rse_settings, [{'name': '4_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_remote_get.raw', 'new_scope': 'user.%s' % self.user},
                                                         {'name': '5_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '5_rse_new.raw'},
                                                         {'name': pfn_a, 'new_name': pfn_a_new},
                                                         {'name': pfn_b, 'new_name': pfn_b_new}], impl=self.impl)
        if (not status and details['user.%s:5_rse_remote_rename.raw' % self.user] and details[pfn_b]) and isinstance(details['user.%s:4_rse_remote_rename.raw' % self.user], type(details[pfn_a])):
            raise details['user.%s:4_rse_remote_rename.raw' % self.user]
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using LFN (FileReplicaAlreadyExists)"""
        mgr.rename(self.rse_settings, {'name': '6_rse_remote_rename.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_remote_get.raw', 'new_scope': 'user.%s' % self.user}, impl=self.impl)

    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '12_rse_remote_rename.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_remote_get.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_rename_mgr_SourceNotFound_multi(self):
        """(RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        pfn_a = list(mgr.lfns2pfns(self.rse_settings, {'name': '12_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_b = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_created.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        status, details = mgr.rename(self.rse_settings, [{'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_new_not_created.raw'},
                                                         {'name': pfn_a, 'new_name': pfn_b}], impl=self.impl)
        if not status and isinstance(details['user.%s:1_rse_not_existing.raw' % self.user], type(details[pfn_a])):
            raise details['user.%s:1_rse_not_existing.raw' % self.user]
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        mgr.rename(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user, 'new_name': '1_rse_new_not_created.raw'}, impl=self.impl)

    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """(RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_not_existing.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '1_rse_new_not_created.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)

    def test_change_scope_mgr_ok_single_lfn(self):
        """(RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        mgr.rename(self.rse_settings, {'name': '1_rse_remote_change_scope.raw', 'scope': 'user.%s' % self.user, 'new_scope': 'group.%s' % self.user}, impl=self.impl)

    def test_change_scope_mgr_ok_single_pfn(self):
        """(RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        pfn = list(mgr.lfns2pfns(self.rse_settings, {'name': '2_rse_remote_change_scope.raw', 'scope': 'user.%s' % self.user}, impl=self.impl).values())[0]
        pfn_new = list(mgr.lfns2pfns(self.rse_settings, {'name': '2_rse_remote_change_scope.raw', 'scope': 'group.%s' % self.user}, impl=self.impl).values())[0]
        mgr.rename(self.rse_settings, {'name': pfn, 'new_name': pfn_new}, impl=self.impl)
