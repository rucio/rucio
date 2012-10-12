# Copyright European Organization for Nuclear Research (CERN)
# #
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# #
# Authors:
# - Angelos Molfetas,  <angelos.molfetas@cern.ch>, 2012
#
from nose.tools import raises, assert_equal
from uuid import uuid4 as uuid

from rucio.common import exception
#from rucio.core.dataset import bulk_register_files, change_file_owner, does_file_exist, get_file_metadata, is_file_obsolete, list_files, obsolete_file
#from rucio.core.dataset import register_dataset, register_file, unregister_dataset, unregister_file
from rucio.core.scope import add_scope, bulk_add_scopes
from rucio.db.session import build_database
from rucio.tests.common import create_accounts, create_tmp_dataset, create_tmp_file
#
#
# class TestFile:
#     def setUp(self):
#         build_database(echo=False)
#         self.user = 'test_user'
#         self.user2 = 'another user'
#         self.user3 = 'user3'
#         self.user_type = 'user'
#         self.scope_misc = 'misc'
#         self.invalid_user = 'invalid_user'
#         self.invalid_scope = 'invalid_scope'
#         self.invalid_file = 'invalid_file'
#         self.to_clean_files = []  # files that eventually need to be cleaned
#         self.to_clean_datasets = []  # datasets that eventually need to be cleaned
#         create_accounts([self.user, self.user2, self.user3], self.user_type)
#         try:
#             add_scope(self.scope_misc, self.user)
#         except exception.Duplicate:
#             pass  # Scope already exists, no need to create it
#
#         # Define two group of scopes
#         self.scope_data_prefix = 'data12_'
#         self.scope_mc_prefix = 'mc12_'
#         self.scope_data_pattern = self.scope_data_prefix + '%'
#         self.scope_mc_pattern = self.scope_mc_prefix + '%'
#         self.scopes_data = [self.scope_data_prefix + str(i) for i in range(5)]
#         self.scopes_mc = [self.scope_mc_prefix + str(i) for i in range(5)]
#         bulk_add_scopes(self.scopes_mc, self.user, skipExisting=True)
#         bulk_add_scopes(self.scopes_data, self.user, skipExisting=True)
#
#         # Create two groups of datasets
#         self.file_data_prefix = 'data12.'
#         self.file_mc_prefix = 'mc12.'
#         self.file_data_pattern = self.file_data_prefix + '%'
#         self.file_mc_pattern = self.file_mc_prefix + '%'
#         self.test_data_files = [self.file_data_prefix + str(i) for i in range(4)]
#         self.test_mc_files = [self.file_mc_prefix + str(i) for i in range(4)]
#         bulk_register_files(self.scopes_data[0], self.test_data_files, self.user, skipExisting=True)
#         bulk_register_files(self.scopes_mc[0], self.test_mc_files, self.user, skipExisting=True)
#
#     def tearDown(self):
#         self.clean_files_and_datasets()
#         for lfn in self.test_mc_files:  # Clean mc datasets
#             unregister_file(self.scopes_mc[0], lfn, self.user)
#         for lfn in self.test_data_files:  # Clean data datasets
#             unregister_file(self.scopes_data[0], lfn, self.user)
#
#     def clean_files_and_datasets(self):
#         # Clean unwanted files and datasets from exceptions
#         for lfn in self.to_clean_files:  # Clean left over files
#             unregister_file(self.scope_misc, lfn, self.user)
#         for dsn in self.to_clean_datasets:  # Clean left over datasets
#             unregister_dataset(self.scope_misc, dsn, self.user)
#
#     # Registering and listing files
#
#     def test_api_register_query_unregister_file(self):
#         """ FILE (CORE): Create and query a file """
#         assert_equal(does_file_exist(self.user, self.scope_misc, self.invalid_file), False)  # Invalid file does not exist
#         lfn = str(uuid())
#         register_file(self.scope_misc, lfn, self.user)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user), True)  # File should exist
#         register_file(self.scopes_data[1], lfn, self.user)  # Register duplicate lfn, but in a different scope
#         assert_equal(does_file_exist(self.scopes_data[1], lfn, self.user), True)  # File should exist
#         unregister_file(self.scope_misc, lfn, self.user)
#         unregister_file(self.scopes_data[1], lfn, self.user)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user), False)  # Deleted file does not exist anymore
#         assert_equal(does_file_exist(self.scopes_data[1], lfn, self.user), False)  # Deleted file does not exist anymore
#
#     def test_api_bulk_register_files(self):
#         """ FILE (CORE): Bulk register files """
#         tmp_scope = 'tmp_scope'
#         try:
#             add_scope(tmp_scope, self.user)
#         except exception.Duplicate:
#             pass  # Scope already exists, no need to create it
#         lfn = str(uuid())
#         lfn2 = str(uuid())
#         lfn3 = str(uuid())
#         bulk_register_files(tmp_scope, [lfn, lfn2], self.user, skipExisting=True)
#         assert_equal(set(list_files(self.user, tmp_scope, "%")), set([lfn, lfn2]))
#         bulk_register_files(tmp_scope, [lfn, lfn2, lfn3], self.user, skipExisting=True)
#         assert_equal(set(list_files(self.user, tmp_scope, "%")), set([lfn, lfn2, lfn3]))
#         self.to_clean_files.extend((lfn, lfn2, lfn3))
#
#     def test_api_list_files(self):
#         """ FILE (CORE): List files in multple scopes """
#
#         self.clean_files_and_datasets()
#         # Test single scope
#         assert_equal(list_files(self.user, self.scopes_mc[0], self.test_mc_files[0]), [self.test_mc_files[0]])  # Single scope, single file
#         assert_equal(list_files(self.user, self.scopes_data[0], self.file_data_pattern), self.test_data_files)  # Single scope, wildcard file pattern
#         assert_equal(list_files(self.user, self.scopes_data[0], "*"), self.test_data_files)  # Single scope, all files (*)
#         assert_equal(list_files(self.user, self.scopes_data[0], None), self.test_data_files)  # Single scope, all files (None)
#         # Test wildcard in scopes
#         assert_equal(list_files(self.user, self.scope_mc_pattern, self.test_mc_files[0]), [self.test_mc_files[0]])  # Wildcard scopes, single file
#         assert_equal(list_files(self.user, self.scope_mc_pattern, self.file_mc_pattern), self.test_mc_files)  # Wildcard scope, wildcard file
#         assert_equal(list_files(self.user, self.scope_mc_pattern, "*"), self.test_mc_files)  # Wildcard scope, all files (*)
#         assert_equal(list_files(self.user, self.scope_mc_pattern, None), self.test_mc_files)  # Wildcard scope, all files (None)
#         # Test all scopes
#         assert_equal(list_files(self.user, "*", self.test_mc_files[0]), [self.test_mc_files[0]])  # All scopes, single file
#         assert_equal(list_files(self.user, "*", self.file_mc_pattern), self.test_mc_files)  # All scopes, wildcard files
#
#     def test_api_change_does_file_exist_owner(self):
#         """ FILE (CORE): Change the owner of a file, get metadata on file """
#         lfn = str(uuid())
#         register_file(self.scope_misc, lfn, self.user)
#         file_metadata = {'owner': self.user, 'obsolete': False}
#         assert_equal(get_file_metadata(self.scope_misc, lfn, self.user), file_metadata)
#         file_metadata['owner'] = self.user2
#         change_file_owner(self.scope_misc, lfn, self.user, self.user2)
#         assert_equal(get_file_metadata(self.scope_misc, lfn, self.user2), file_metadata)
#         unregister_file(self.scope_misc, lfn, self.user)
#
#     # Does file exist
#
#     def test_api_does_file_exist_normal_and_obsolete(self):
#         """ FILE (CORE): Check if file exists """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user), True)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user, search_obsolete=False), True)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user, search_obsolete=True), False)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user, search_obsolete=None), True)
#         obsolete_file(self.scope_misc, lfn, self.user)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user), False)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user, search_obsolete=False), False)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user, search_obsolete=True), True)
#         assert_equal(does_file_exist(self.scope_misc, lfn, self.user, search_obsolete=None), True)
#
#     # Obsoleting files
#
#     def test_api_obsolete_file_and_list(self):
#         """ FILE (CORE): List obsolete file """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         assert_equal(list_files(self.user, self.scope_misc, lfn), [lfn])
#         obsolete_file(self.scope_misc, lfn, self.user)
#         assert_equal(list_files(self.user, self.scope_misc, lfn), [])
#
#     def test_api_obsolete_dataset_and_list(self):
#         """ FILE (CORE): Get obsolete status of a dataset """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         assert_equal(is_file_obsolete(self.scope_misc, lfn, self.user), False)
#         obsolete_file(self.scope_misc, lfn, self.user)
#         assert_equal(is_file_obsolete(self.scope_misc, lfn, self.user), True)
#
#     # Error Handling: Obsolete file and getting file obsolete state
#
#     @raises(exception.FileNotFound)
#     def test_api_check_if_file_is_obsolete(self):
#         """ FILE (CORE): Check obsolete state of invalid file """
#         is_file_obsolete(self.scope_misc, self.invalid_file, self.user)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_check_if_file_is_obsolete_invalid_scope(self):
#         """ FILE (CORE): Check obsolete state of file with invalid scope """
#         is_file_obsolete(self.invalid_scope, self.invalid_file, self.user)
#
#     @raises(exception.NotAFile)
#     def test_api_check_if_file_is_obsolete_not_a_file(self):
#         """ FILE (CORE): Check obsolete state of dataset using file obsolete file query api """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         is_file_obsolete(self.scope_misc, dsn, self.user)
#
#     @raises(exception.FileNotFound)
#     def test_api_obsolete_invalid_file(self):
#         """ FILE (CORE): Obsolete invalid file """
#         obsolete_file(self.scope_misc, self.invalid_file, self.user)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_obsolete_invalid_scope(self):
#         """ FILE (CORE): Obsolete file with invalid scope """
#         obsolete_file(self.invalid_scope, self.invalid_file, self.user)
#
#     @raises(exception.FileObsolete)
#     def test_api_obsolete_file_already_obsolete(self):
#         """ FILE (CORE): Obsoleting file which is already obsolete """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         obsolete_file(self.scope_misc, lfn, self.user)
#         obsolete_file(self.scope_misc, lfn, self.user)
#
#     @raises(exception.NotAFile)
#     def test_api_obsolete_dataset_specify_file(self):
#         """ FILE (CORE): Obsoleting dataset using file obsoletion core api """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_files)
#         obsolete_file(self.scope_misc, dsn, self.user)
#
#     # Error Handling: Dataset registration
#
#     @raises(exception.FileAlreadyExists)
#     def test_api_bulk_register_file_duplicate_exists(self):
#         """ FILE (CORE): Bulk register duplicate files without duplicate ignore option """
#         tmp_scope = 'tmp_scope2'
#         try:
#             add_scope(tmp_scope, self.user)
#         except exception.Duplicate:
#             pass  # Scope already exists, no need to create it
#         lfn = str(uuid())
#         lfn2 = str(uuid())
#         register_file(tmp_scope, lfn2, self.user)
#         bulk_register_files(tmp_scope, [lfn, lfn2], self.user, skipExisting=False)
#
#     @raises(exception.AccountNotFound)
#     def test_api_register_dataset_invalid_user(self):
#         """ FILE (CORE): Register file with invalid account name """
#         lfn = str(uuid())
#         register_file(self.scope_misc, lfn, self.invalid_user)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_register_dataset_invalid_scope(self):
#         """ FILE (CORE): Register file with scope that does not exist """
#         lfn = str(uuid())
#         register_file(self.invalid_scope, lfn, self.user)
#
#     @raises(exception.FileAlreadyExists)
#     def test_api_create_duplicate_dataset(self):
#         """ FILE (CORE): Register a file with the same scope and name as another file"""
#         lfn = str(uuid())
#         self.to_clean_files.append(lfn)
#         register_file(self.scope_misc, lfn, self.user)
#         register_file(self.scope_misc, lfn, self.user)
#
#     @raises(exception.DatasetAlreadyExists)
#     def test_api_create_clashing_dsn_lfn(self):
#         """ FILE (CORE): Register a file with the same scope and name as an existing dataset"""
#         label = str(uuid())
#         self.to_clean_files.append(label)
#         self.to_clean_datasets.append(label)
#         register_dataset(self.scope_misc, label, self.user)
#         register_file(self.scope_misc, label, self.user)
#
#     # Error Handling: Get dataset metadata
#
#     @raises(exception.FileNotFound)
#     def test_api_get_file_metadata_invalid_file(self):
#         """ FILE (CORE): Get metadata on invalid file """
#         get_file_metadata(self.scope_misc, self.invalid_file, self.user)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_get_dataset_metadata_invalid_scope(self):
#         """FILE (CORE): Get file metadata using invalid scope """
#         get_file_metadata(self.invalid_scope, self.invalid_file, self.user)
#
#     # Error Handling: Change file owner
#
#     @raises(exception.NotAFile)
#     def test_api_change_file_owner_specify_file_instead(self):
#         """ FILE (CORE): Change the owner of a file by specifying a dataset name instead """
#         label = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_file_owner(self.scope_misc, label, self.user, self.user2)
#
#     @raises(exception.AccountNotFound)
#     def test_api_change_file_owner_invalid_new_account(self):
#         """ FILE (CORE): Change the owner of a file to a new invalid account """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_file_owner(self.scope_misc, lfn, self.user, self.invalid_user)
#
#     @raises(exception.AccountNotFound)
#     def test_api_change_file_owner_invalid_old_account(self):
#         """ FILE (CORE): Change file owner by providing invalid account for current owner """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_file_owner(self.scope_misc, lfn, self.invalid_user, self.user2)
#
#     @raises(exception.NoPermissions)
#     def test_api_change_file_owner_account_not_owner(self):
#         """ FILE (CORE): Change file owner by providing as the current owner a valid account that is not the current owner """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_file_owner(self.scope_misc, lfn, self.user2, self.user3)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_change_file_owner_invalid_scope(self):
#         """ FILE (CORE): Change file in an invalid scope """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_file_owner(self.invalid_scope, lfn, self.user, self.user2)
#
#     @raises(exception.FileNotFound)
#     def test_api_change_file_owner_invalid_file(self):
#         """ FILE (CORE): Change the owner of a non existing file in a scope """
#         change_file_owner(self.scope_misc, self.invalid_file, self.user, self.user2)
#
#     @raises(exception.FileObsolete)
#     def test_api_change_owner_of_obsolete_file(self):
#         """ FILE (CORE): Change the owner of an obsolete file """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         obsolete_file(self.scope_misc, lfn, self.user)
#         change_file_owner(self.scope_misc, lfn, self.user, self.user2)
