# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas,  <angelos.molfetas@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from uuid import uuid4 as uuid

from nose.tools import raises, assert_equal

from rucio.common import exception
from rucio.core.account import add_account
# from rucio.core.dataset import add_files_to_dataset, bulk_register_datasets, get_dataset_metadata, is_name_obsolete
# from rucio.core.dataset import list_files_in_dataset, obsolete_dataset, obsolete_file, obsolete_name
# from rucio.core.dataset import register_dataset, register_file, unregister_dataset, unregister_file
# from rucio.core.dataset import change_name_owner, does_name_exist, get_name_metadata, list_names
from rucio.core.scope import add_scope, bulk_add_scopes
from rucio.db.session import build_database, destroy_database
from rucio.tests.common import create_tmp_dataset, create_tmp_file
#
#
# class TestName:
#
#     def setUp(self):
#         build_database(echo=False)
#
#         self.user = 'test_user'
#         add_account(self.user, 'user')
#
#         self.user2 = 'another_usr'
#         add_account(self.user2, 'user')
#
#         self.user3 = 'one_more_usr'
#         add_account(self.user3, 'user')
#
#         self.user_type = 'user'
#         self.scope_misc = 'misc'
#         self.invalid_user = 'invalid_user'
#         self.invalid_scope = 'invalid_scope'
#         self.invalid_dsn = 'invalid_dataset'
#         self.invalid_file = 'invalid_file'
#         self.to_clean_files = []  # files that eventually need to be cleaned
#         self.to_clean_datasets = []  # datasetss that eventually need to be cleaned
#
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
#         self.dataset_data_prefix = 'data12.'
#         self.dataset_mc_prefix = 'mc12.'
#         self.dataset_data_pattern = self.dataset_data_prefix + '%'
#         self.dataset_mc_pattern = self.dataset_mc_prefix + '%'
#         self.test_data_dsts = [self.dataset_data_prefix + str(i) for i in range(4)]
#         self.test_mc_dsts = [self.dataset_mc_prefix + str(i) for i in range(4)]
#         bulk_register_datasets(self.scopes_data[0], self.test_data_dsts, self.user, skipExisting=True)
#         bulk_register_datasets(self.scopes_mc[0], self.test_mc_dsts, self.user, skipExisting=True)
#
#     def tearDown(self):
#         destroy_database(echo=False)
#
#     def clean_files_and_datasets(self):
#         # Clean unwanted datasets from exceptions
#         for dst in self.to_clean_datasets:  # Clean left over datasets
#             unregister_dataset(self.scope_misc, dst, self.user)
#         for lfn in self.to_clean_files:  # Clean left over files
#             unregister_file(self.scope_misc, lfn, self.user)
#
#     # Register and query names
#
#     def test_api_register_query_unregister_dataset(self):
#         """ NAME (CORE): Create and query for names """
#         dsn = str(uuid())
#         # Test registering and quering whether datasets exists
#         register_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(does_name_exist(self.scope_misc, dsn, self.user), True)  # Dataset name exists
#         assert_equal(does_name_exist(self.scope_misc, self.invalid_dsn, self.user), False)  # Invalid dataset name does not exist
#         # Unregister dataset
#         unregister_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(does_name_exist(self.user, self.scope_misc, dsn), False)  # Deleted dataset name does not exist anymore
#         lfn = str(uuid())
#         # Test registering and quering whether file exists
#         register_file(self.scope_misc, lfn, self.user)
#         assert_equal(does_name_exist(self.scope_misc, lfn, self.user), True)  # File name exists
#         assert_equal(does_name_exist(self.scope_misc, self.invalid_file, self.user), False)  # Invalid file name does not exist
#         # Unregister file
#         unregister_file(self.scope_misc, lfn, self.user)
#         assert_equal(does_name_exist(self.user, self.scope_misc, lfn), False)  # Deleted file name does not exist anymore
#
#     def test_api_list_names(self):
#         """ NAME (CORE): List names in multple scopes """
#         self.clean_files_and_datasets()
#         # Test single scope
#         assert_equal(list_names(self.user, self.scopes_mc[0], self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Single scope, single dataset
#         assert_equal(list_names(self.user, self.scopes_data[0], self.dataset_data_pattern), self.test_data_dsts)  # Single scope, wildcard dst pattern
#         assert_equal(list_names(self.user, self.scopes_data[0], "*"), self.test_data_dsts)  # Single scope, all dataset (*)
#         assert_equal(list_names(self.user, self.scopes_data[0], None), self.test_data_dsts)  # Single scope, all dataset (None)
#         # Test wildcard in scopes
#         assert_equal(list_names(self.user, self.scope_mc_pattern, self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Wildcard scopes, single dataset
#         assert_equal(list_names(self.user, self.scope_mc_pattern, self.dataset_mc_pattern), self.test_mc_dsts)  # Wildcard scope, wildcard dataset
#         assert_equal(list_names(self.user, self.scope_mc_pattern, "*"), self.test_mc_dsts)  # Wildcard scope, all dataset (*)
#         assert_equal(list_names(self.user, self.scope_mc_pattern, None), self.test_mc_dsts)  # Wildcard scope, all dataset (None)
#         # Test all scopes
#         assert_equal(list_names(self.user, "*", self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # All scopes, single dataset
#         assert_equal(list_names(self.user, "*", self.dataset_mc_pattern), self.test_mc_dsts)  # All scopes, wildcard dataset
#
#     def test_api_change_does_name_exist_owner(self):
#         """ NAME (CORE): Change the owner of an name, get metadata on name """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         dst_metadata = {'owner': self.user, 'obsolete': False, 'type': NameType.DATASET, 'monotonic': False}
#         assert_equal(get_name_metadata(self.scope_misc, dsn, self.user), dst_metadata)
#         dst_metadata['owner'] = self.user2
#         change_name_owner(self.scope_misc, dsn, self.user, self.user2)
#         assert_equal(get_name_metadata(self.scope_misc, dsn, self.user2), dst_metadata)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         file_metadata = {'owner': self.user, 'obsolete': False, 'type': NameType.FILE}
#         assert_equal(get_name_metadata(self.scope_misc, lfn, self.user), file_metadata)
#         file_metadata['owner'] = self.user2
#         change_name_owner(self.scope_misc, lfn, self.user, self.user2)
#         assert_equal(get_name_metadata(self.scope_misc, lfn, self.user2), file_metadata)
#
#     def test_api_get_name_dataset_metadata_invalid_scope(self):
#         """ NAME (CORE): Get name metadata on invalid scope """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         assert_equal(get_name_metadata(self.invalid_scope, dsn, self.user), None)
#         assert_equal(get_name_metadata(self.invalid_scope, lfn, self.user), None)
#
#     # Obsoleting names
#
#     def test_api_obsolete_dataset_and_list(self):
#         """ NAME (CORE): List names which are not obsolete """
#         scope_tmp = 'some_scope'
#         add_scope(scope_tmp, self.user)
#         dsn = create_tmp_dataset(scope_tmp, self.user, self.to_clean_datasets)
#         assert_equal(list_names(self.user, scope_tmp, dsn), [dsn])
#         obsolete_name(scope_tmp, dsn, self.user)
#         assert_equal(list_names(self.user, scope_tmp, dsn), [])
#         lfn = create_tmp_file(scope_tmp, self.user, self.to_clean_files)
#         assert_equal(list_names(self.user, scope_tmp, lfn), [lfn])
#         obsolete_name(scope_tmp, lfn, self.user)
#         assert_equal(list_names(self.user, scope_tmp, lfn), [])
#
#     def test_api_obsoletes_dataset_and_files_and_check_obsolete_status(self):
#         """ NAME (CORE): Get obsolete status of an names """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         assert_equal(is_name_obsolete(self.scope_misc, dsn, self.user), False)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(is_name_obsolete(self.scope_misc, dsn, self.user), True)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         assert_equal(is_name_obsolete(self.scope_misc, lfn, self.user), False)
#         obsolete_file(self.scope_misc, lfn, self.user)
#         assert_equal(is_name_obsolete(self.scope_misc, lfn, self.user), True)
#         lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         assert_equal(is_name_obsolete(self.scope_misc, lfn2, self.user), False)
#         obsolete_name(self.scope_misc, lfn2, self.user)
#         assert_equal(is_name_obsolete(self.scope_misc, lfn2, self.user), True)
#
#     def test_api_obsoletes_dataset_and_files_and_list_obsolete_status(self):
#         """ NAME (CORE): List obsolete names """
#         tmp_scope = 'next scope'
#         add_scope(tmp_scope, self.user)
#         dsn = create_tmp_dataset(tmp_scope, self.user, self.to_clean_datasets)
#         obsolete_dataset(tmp_scope, dsn, self.user)
#         lfn = create_tmp_file(tmp_scope, self.user, self.to_clean_files)
#         obsolete_file(tmp_scope, lfn, self.user)
#         lfn2 = create_tmp_file(tmp_scope, self.user, self.to_clean_files)
#         obsolete_name(tmp_scope, lfn2, self.user)
#         dsn2 = create_tmp_dataset(tmp_scope, self.user, self.to_clean_files)
#         assert_equal(list_names(nameScope=tmp_scope, accountName=self.user, obsolete=False), [dsn2])
#         assert_equal(set(list_names(nameScope=tmp_scope, accountName=self.user, obsolete=True)), set([dsn, lfn, lfn2, dsn2]))
#
#     def test_api_obsolete_dataset_and_list_files(self):
#         """ NAME (CORE): List files in dataset, which was obsoleted using the name obsolete API """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([lfn, ], self.scope_misc, dsn, self.user, self.scope_misc)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [(self.scope_misc, lfn), ])
#         obsolete_name(self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [])
#
#     def test_api_obsolete_file_and_list_files_in_dataset(self):
#         """ DATASET (CORE): Obsolete one of the files in a dataset using name obsolete API and list files in dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([lfn, lfn2], self.scope_misc, dsn, self.user, self.scope_misc)
#         obsolete_name(self.scope_misc, lfn2, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [(self.scope_misc, lfn), ])
#
#     def test_api_obosolete_names_and_do_wildcard_search(self):
#         """ NAME (CORE): List obsolete names with scope and name wildcard search """
#         dsn1 = 'test1 %s' % str(uuid())
#         dsn2 = 'test1 %s' % str(uuid())
#         lfn1 = 'test1 %s' % str(uuid())
#         lfn2 = 'test1 %s' % str(uuid())
#         try:
#             add_scope('testing_scope', self.user)
#         except exception.Duplicate:
#             pass
#         register_dataset('testing_scope', dsn1, self.user)
#         register_dataset('testing_scope', dsn2, self.user)
#         register_file('testing_scope', lfn1, self.user)
#         register_file('testing_scope', lfn2, self.user)
#         assert_equal(set(list_names(self.user, 'testing*', 'test*')), set([dsn1, dsn2, lfn1, lfn2]))
#         assert_equal(set(list_names(self.user, 'testing*', 'test*', obsolete=False)), set([dsn1, dsn2, lfn1, lfn2]))
#         assert_equal(set(list_names(self.user, 'testing*', 'test*', obsolete=True)), set([dsn1, dsn2, lfn1, lfn2]))
#         obsolete_name('testing_scope', dsn1, self.user)
#         obsolete_name('testing_scope', dsn2, self.user)
#         obsolete_name('testing_scope', lfn1, self.user)
#         obsolete_name('testing_scope', lfn2, self.user)
#         assert_equal(list_names(self.user, 'testing*', 'test*', obsolete=False), [])
#         assert_equal(list_names(self.user, 'testing*', 'test*'), [])
#         assert_equal(set(list_names(self.user, 'testing*', 'test*', obsolete=True)), set([dsn1, dsn2, lfn1, lfn2]))
#
#    # Error Handling: Obsolete datasets and getting dataset obsolete state
#
#     @raises(exception.NameNotFound)
#     def test_api_check_if_name_is_obsolete(self):
#         """ NAME (CORE): Check obsolete state of invalid name """
#         is_name_obsolete(self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_check_if_dataset_is_obsolete_invalid_scope(self):
#         """ NAME (CORE): Check obsolete state of name with invalid scope """
#         is_name_obsolete(self.invalid_scope, self.invalid_dsn, self.user)
#
#     @raises(exception.NameNotFound)
#     def test_api_obsolete_invalid_name(self):
#         """ NAME (CORE): Obsolete invalid name """
#         obsolete_name(self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_obsolete_node_invalid_scope(self):
#         """ NAME (CORE): Obsolete dataset with invalid scope """
#         obsolete_name(self.invalid_scope, self.invalid_dsn, self.user)
#
#     @raises(exception.DatasetObsolete)
#     def test_api_obsolete_name_dataset_already_obsolete(self):
#         """ NAME (CORE): Obsoleting dataset which is already obsolete """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         obsolete_name(self.scope_misc, dsn, self.user)
#         obsolete_name(self.scope_misc, dsn, self.user)
#
#     @raises(exception.FileObsolete)
#     def test_api_obsolete_name_file_already_obsolete(self):
#         """ NAME (CORE): Obsoleting file which is already obsolete """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         obsolete_name(self.scope_misc, lfn, self.user)
#         obsolete_name(self.scope_misc, lfn, self.user)
#
#     # Error Handling: Get dataset metadata
#
#     @raises(exception.DatasetNotFound)
#     def test_api_get_name_dataset_metadata_invalid_dataset(self):
#         """ NAME (CORE): Get metadata on invalid name """
#         get_dataset_metadata(self.scope_misc, self.invalid_dsn, self.user)
#
#     # Error Handling: Change dataset owner
#
#     @raises(exception.AccountNotFound)
#     def test_api_change_name_dataset_owner_invalid_new_account(self):
#         """ NAME (CORE): Change the owner of a name (dataset) to a new invalid account """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_name_owner(self.scope_misc, dsn, self.user, self.invalid_user)
#
#     @raises(exception.AccountNotFound)
#     def test_api_change_name_file_owner_invalid_new_account(self):
#         """ NAME (CORE): Change the owner of a name (file) to a new invalid account """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_name_owner(self.scope_misc, lfn, self.user, self.invalid_user)
#
#     @raises(exception.AccountNotFound)
#     def test_api_change_name_dataset_owner_invalid_old_account(self):
#         """ NAME (CORE): Change name (dataset) owner by providing invalid account for current owner """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_name_owner(self.scope_misc, dsn, self.invalid_user, self.user2)
#
#     @raises(exception.AccountNotFound)
#     def test_api_change_name_file_owner_invalid_old_account(self):
#         """ NAME (CORE): Change file (owner) by providing invalid account for current owner """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_name_owner(self.scope_misc, lfn, self.invalid_user, self.user2)
#
#     @raises(exception.NoPermissions)
#     def test_api_change_name_dataset_owner_account_not_owner(self):
#         """ NAME (CORE): Change name (dataset) owner by providing as current owner a valid account that is not the current owner """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_name_owner(self.scope_misc, dsn, self.user2, self.user3)
#
#     @raises(exception.NoPermissions)
#     def test_api_change_name_file_owner_account_not_owner(self):
#         """ NAME (CORE): Change name (file) owner by providing as current owner a valid account that is not the current owner """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_name_owner(self.scope_misc, lfn, self.user2, self.user3)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_change_name_dataset_owner_invalid_scope(self):
#         """ NAME (CORE): Change name (dataset) in an invalid scope """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_name_owner(self.invalid_scope, dsn, self.user, self.user2)
#
#     @raises(exception.ScopeNotFound)
#     def test_api_change_name_file_owner_invalid_scope(self):
#         """ NAME (CORE): Change name (file) in an invalid scope """
#         lfn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_files)
#         change_name_owner(self.invalid_scope, lfn, self.user, self.user2)
#
#     @raises(exception.NameNotFound)
#     def test_api_change_dataset_owner_invalid_dsn(self):
#         """ NAME (CORE): Change the owner of a non existing name in a scope """
#         change_name_owner(self.scope_misc, self.invalid_dsn, self.user, self.user2)
#
#     @raises(exception.FileObsolete)
#     def test_api_name_change_owner_of_obsolete_file(self):
#         """ NAME (CORE): Change the owner of an obsolete file using name change owner API"""
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         obsolete_file(self.scope_misc, lfn, self.user)
#         change_name_owner(self.scope_misc, lfn, self.user, self.user2)
#
#     @raises(exception.DatasetObsolete)
#     def test_api_name_change_owner_of_obsolete_dataset(self):
#         """ FILE (CORE): Change the owner of an obsolete dataset using name change owner API"""
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         change_name_owner(self.scope_misc, dsn, self.user, self.user2)
