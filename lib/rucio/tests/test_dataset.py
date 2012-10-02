# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps
from nose.tools import raises, assert_equal, assert_false, assert_true
from paste.fixture import TestApp

from rucio.client.accountclient import AccountClient
from rucio.client.datasetclient import DatasetClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import AccountNotFound, DatasetAlreadyExists,\
    DatasetIsMonotonic, DatasetNotFound, DatasetObsolete,\
    Duplicate, FileAlreadyExists, FileNotFound, NameNotFound,\
    InputValidationError, NoPermissions, NotADataset, ScopeNotFound
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account
from rucio.core.identity import add_account_identity, add_identity
from rucio.core.dataset import add_files_to_dataset, build_name_list, bulk_register_datasets, bulk_register_files, change_dataset_owner,\
    delete_files_from_dataset, does_dataset_exist, get_dataset_metadata, get_dataset_owner, list_datasets,\
    is_dataset_monotonic, is_dataset_obsolete, is_file_obsolete, list_files_in_dataset, obsolete_dataset, obsolete_file,\
    register_dataset, unregister_dataset, unregister_file
from rucio.core.scope import add_scope, bulk_add_scopes
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.tests.common import create_accounts, create_tmp_dataset, create_tmp_file, get_auth_token
from rucio.web.rest.dataset import app as dataset_web_app


class TestDataset_CORE:

    @classmethod
    def setUpClass(cls):
        build_database(echo=False)
        create_root_account()

    @classmethod
    def tearDownClass(cls):
        destroy_database(echo=False)

    def setUp(self):
        #build_database(echo=False)
        self.user = 'test_user'
        self.user2 = 'another_usr'
        self.user3 = 'one_more_usr'
        self.user_type = 'user'
        self.scope_misc = 'misc'
        self.invalid_user = 'invalid_user'
        self.invalid_scope = 'invalid_scope'
        self.invalid_dsn = 'invalid_dataset'
        self.to_clean_files = []  # files that eventually need to be cleaned
        self.to_clean_datasets = []  # datasets that eventually need to be cleaned
        create_accounts([self.user, self.user2, self.user3], self.user_type)
        try:
            add_scope(self.scope_misc, self.user)
        except Duplicate:
            pass  # Scope already exists, no need to create it

        # Define two group of scopes
        self.scope_data_prefix = 'data12_'
        self.scope_mc_prefix = 'mc12_'
        self.scope_data_pattern = self.scope_data_prefix + '%'
        self.scope_mc_pattern = self.scope_mc_prefix + '%'
        self.scopes_data = [self.scope_data_prefix + str(i) for i in range(5)]
        self.scopes_mc = [self.scope_mc_prefix + str(i) for i in range(5)]
        bulk_add_scopes(self.scopes_mc, self.user, skipExisting=True)
        bulk_add_scopes(self.scopes_data, self.user, skipExisting=True)

        # Create two groups of datasets
        self.dataset_data_prefix = 'data12.'
        self.dataset_mc_prefix = 'mc12.'
        self.dataset_data_pattern = self.dataset_data_prefix + '%'
        self.dataset_mc_pattern = self.dataset_mc_prefix + '%'
        self.test_data_dsts = [self.dataset_data_prefix + str(i) for i in range(4)]
        self.test_mc_dsts = [self.dataset_mc_prefix + str(i) for i in range(4)]
        bulk_register_datasets(self.scopes_data[0], self.test_data_dsts, self.user, skipExisting=True)
        bulk_register_datasets(self.scopes_mc[0], self.test_mc_dsts, self.user, skipExisting=True)

        # Create a group of file for dataset associations
        self.interesting_files_prefix = 'interesting_files.'
        self.test_interesting_files = [self.interesting_files_prefix + str(i) for i in range(20)]
        bulk_register_files(self.scope_misc, self.test_interesting_files, self.user, skipExisting=True)

    def tearDown(self):
        self.clean_files_and_datasets()
        for dst in self.test_mc_dsts:  # Clean mc datasets
            unregister_dataset(self.scopes_mc[0], dst, self.user)
        for dst in self.test_data_dsts:  # Clean data datasets
            unregister_dataset(self.scopes_data[0], dst, self.user)
        for file in self.test_interesting_files:  # Clean interesting files
            unregister_file(self.scope_misc, file, self.user)

    def clean_files_and_datasets(self):
        # Clean unwanted datasets from exceptions
        for dst in self.to_clean_datasets:  # Clean left over datasets
            unregister_dataset(self.scope_misc, dst, self.user)
        for lfn in self.to_clean_files:  # Clean left over files
            unregister_file(self.scope_misc, lfn, self.user)

    # Register and list datasets

    def test_api_register_query_unregister_dataset(self):
        """ DATASET (CORE): Create and query for datasets """
        dsn = str(uuid())
        # Test registering and quering whether datasets exists
        register_dataset(self.scope_misc, dsn, self.user)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), True)  # Dataset exists
        assert_equal(does_dataset_exist(self.scope_misc, self.invalid_dsn), False)  # Invalid dataset does not exist
        # Unregister dataset
        unregister_dataset(self.scope_misc, dsn, self.user)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), False)  # Deleted dataset does not exist anymore

#     def test_api_bulk_register_datasets(self):
#         """ DATASET (CORE): Bulk register datasets """
#         try:
#             add_scope(self.scope_misc, self.user)
#         except Duplicate:
#             pass  # Scope already exists, no need to create it
#         dsn = str(uuid())
#         dsn2 = str(uuid())
#         dsn3 = str(uuid())
#         bulk_register_datasets(self.scope_misc, [dsn, dsn2], self.user, skipExisting=True)
#         assert_equal(set(list_datasets(self.user, self.scope_misc, "%")), set([dsn, dsn2]))
#         bulk_register_datasets(self.scope_misc, [dsn, dsn2, dsn3], self.user, skipExisting=True)
#         assert_equal(set(list_datasets(self.user, self.scope_misc, "%")), set([dsn, dsn2, dsn3]))
#         self.to_clean_datasets.extend((dsn, dsn2, dsn3))
#
#     def test_api_list_datasets(self):
#         """ DATASET (CORE): List datasets in multple scopes """
#         self.clean_files_and_datasets()
#         # Test single scope
#         assert_equal(list_datasets(self.user, self.scopes_mc[0], self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Single scope, single dataset
#         assert_equal(list_datasets(self.user, self.scopes_data[0], self.dataset_data_pattern), self.test_data_dsts)  # Single scope, wildcard dst pattern
#         assert_equal(list_datasets(self.user, self.scopes_data[0], "*"), self.test_data_dsts)  # Single scope, all dataset (*)
#         assert_equal(list_datasets(self.user, self.scopes_data[0], None), self.test_data_dsts)  # Single scope, all dataset (None)
#         # Test wildcard in scopes
#         assert_equal(list_datasets(self.user, self.scope_mc_pattern, self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Wildcard scopes, single dataset
#         assert_equal(list_datasets(self.user, self.scope_mc_pattern, self.dataset_mc_pattern), self.test_mc_dsts)  # Wildcard scope, wildcard dataset
#         assert_equal(list_datasets(self.user, self.scope_mc_pattern, "*"), self.test_mc_dsts)  # Wildcard scope, all dataset (*)
#         assert_equal(list_datasets(self.user, self.scope_mc_pattern, None), self.test_mc_dsts)  # Wildcard scope, all dataset (None)
#         # Test all scopes
#         assert_equal(list_datasets(self.user, "*", self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # All scopes, single dataset
#         assert_equal(list_datasets(self.user, "*", self.dataset_mc_pattern), self.test_mc_dsts)  # All scopes, wildcard dataset
#
#     # Does dataset exist
#
#     def test_api_does_dataset_exist_normal_and_obsolete(self):
#         """ DATASET (CORE): Check if dataset exists """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn), True)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn, search_obsolete=False), True)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn, search_obsolete=True), False)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn, search_obsolete=None), True)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn), False)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn, search_obsolete=False), False)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn, search_obsolete=True), True)
#         assert_equal(does_dataset_exist(self.scope_misc, dsn, search_obsolete=None), True)
#
#     # Dataset owner
#
#     def test_api_change_owner_check_dataset_metadata(self):
#         """ DATASET (CORE): Change the owner of a dataset, get metadata on dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         dst_metadata = {'owner': self.user, 'obsolete': False, 'monotonic': False}
#         assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
#         dst_metadata['owner'] = self.user2
#         change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)
#         assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user2), dst_metadata)
#
#     def test_api_change_owner_get_dataset_owner(self):
#         """ DATASET (CORE): Change the owner of a dataset, get the owner of the dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)
#         change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)
#         assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user2), self.user2)
#
#     # ADD FILES AND DATASETS TO DATASETS
#
#     def test_api_add_and_delete_files_to_dataset(self):
#         """ DATASET (CORE): Add and remove a file to a dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         dsn2 = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [(self.scope_misc, lfn), ])
#         delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [])
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn2), [])
#
#     def test_api_add_multiple_files_to_dataset(self):
#         """ DATASET (CORE): Add and remove multiple files to a dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         file_list = build_name_list(self.scope_misc, self.test_interesting_files)
#         add_files_to_dataset(file_list, self.scope_misc, dsn, self.user)
#         assert_equal(set(list_files_in_dataset(self.scope_misc, dsn)), set(file_list))
#         delete_files_from_dataset(file_list, self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [])
#
#     def test_api_add_dataset_to_a_dataset(self):
#         """ DATASET (CORE): Add a dataset to another dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         file_list = build_name_list(self.scope_misc, self.test_interesting_files)
#         add_files_to_dataset(file_list, self.scope_misc, dsn, self.user)
#         dsn2 = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         add_files_to_dataset([dsn, ], self.scope_misc, dsn2, self.user, self.scope_misc)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn2), list_files_in_dataset(self.scope_misc, dsn))
#
#     # Monotonic datasets and obsoleting datasets
#
#     def test_api_create_monotonic_and_non_monotonic_dataset(self):
#         """ DATASET (CORE): Create monotonic dataset and check metadata """
#         dsn = str(uuid())
#         register_dataset(self.scope_misc, dsn, self.user, monotonic=True)
#         dst_metadata = {'owner': self.user, 'obsolete': False, 'monotonic': True}
#         assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
#         unregister_dataset(self.scope_misc, dsn, self.user)
#         dsn = str(uuid())
#         register_dataset(self.scope_misc, dsn, self.user, monotonic=False)
#         dst_metadata = {'owner': self.user, 'obsolete': False, 'monotonic': False}
#         assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
#         unregister_dataset(self.scope_misc, dsn, self.user)
#
#     def test_api_delete_file_from_non_monotonic_dataset(self):
#         """ DATASET (CORE): Delete a file from a dataset that is not monotonic """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=False)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [(self.scope_misc, lfn), ])
#         delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [])
#
#     def test_api_check_if_dataset_is_monotonic(self):
#         """ DATASET (CORE): Check whether dataset is monotonic """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=True)
#         assert_equal(is_dataset_monotonic(self.scope_misc, dsn, self.user), True)
#         dsn2 = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=False)
#         assert_equal(is_dataset_monotonic(self.scope_misc, dsn2, self.user), False)
#
#     def test_api_obsolete_dataset_and_list(self):
#         """ DATASET (CORE): List obsolete dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         assert_equal(list_datasets(self.user, self.scope_misc, dsn), [dsn])
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(list_datasets(self.user, self.scope_misc, dsn), [])
#
#     def test_api_obsolete_dataset_status(self):
#         """ DATASET (CORE): Get obsolute status of a dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         assert_equal(is_dataset_obsolete(self.scope_misc, dsn, self.user), False)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(is_dataset_obsolete(self.scope_misc, dsn, self.user), True)
#
#     def test_api_obsolete_dataset_and_list_files(self):
#         """ DATASET (CORE): List files in obsolete dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([lfn, ], self.scope_misc, dsn, self.user, self.scope_misc)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [(self.scope_misc, lfn), ])
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [])
#
#     def test_api_obsolete_file_and_list_files_in_dataset(self):
#         """ DATASET (CORE): Obsolete one of the files in a dataset and list files in dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([lfn, lfn2], self.scope_misc, dsn, self.user, self.scope_misc)
#         obsolete_file(self.scope_misc, lfn2, self.user)
#         assert_equal(list_files_in_dataset(self.scope_misc, dsn), [(self.scope_misc, lfn), ])
#
#     # Error Handling: Check if dataset exists
#
#     @raises(InputValidationError)
#     def test_api_check_if_dataset_exists(self):
#         """ DATASET (CORE): Check if dataset exists, but enter incorrect search obsolete parameter """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         does_dataset_exist(self.scope_misc, dsn, search_obsolete='everything')
#
#     # Error Handling: Monotonic datasets
#
#     @raises(DatasetNotFound)
#     def test_api_check_monotonic_invalid_dataset(self):
#         """ DATASET (CORE): Check monotonic state of invalid dataset """
#         is_dataset_monotonic(self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(ScopeNotFound)
#     def test_api_check_monotonic_invalid_scope(self):
#         """ DATASET (CORE): Check monotonic state of dataset in invalid scope """
#         is_dataset_monotonic(self.invalid_scope, self.invalid_dsn, self.user)
#
#     @raises(NotADataset)
#     def test_api_check_monotonic_dataset_is_a_file(self):
#         """ DATASET (CORE): Check monotonic state of a file """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         is_dataset_monotonic(self.scope_misc, lfn, self.user)
#
#     # Error Handling: Obsolete datasets and getting dataset obsolete state
#
#     @raises(DatasetNotFound)
#     def test_api_check_if_dataset_is_obsolete(self):
#         """ DATASET (CORE): Check obsolete state of invalid dataset """
#         is_dataset_obsolete(self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(ScopeNotFound)
#     def test_api_check_if_dataset_is_obsolete_invalid_scope(self):
#         """ DATASET (CORE): Check obsolete state of dataset with invalid scope """
#         is_dataset_obsolete(self.invalid_scope, self.invalid_dsn, self.user)
#
#     @raises(NotADataset)
#     def test_api_check_if_dataset_is_obsolete_not_a_dataset(self):
#         """ DATASET (CORE): Check obsolete state of file using dataset obsolete query api """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         is_dataset_obsolete(self.scope_misc, lfn, self.user)
#
#     @raises(DatasetNotFound)
#     def test_api_obsolete_invalid_dataset(self):
#         """ DATASET (CORE): Obsolete invalid dataset """
#         obsolete_dataset(self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(ScopeNotFound)
#     def test_api_obsolete_invalid_scope(self):
#         """ DATASET (CORE): Obsolete dataset with invalid scope """
#         obsolete_dataset(self.invalid_scope, self.invalid_dsn, self.user)
#
#     @raises(DatasetObsolete)
#     def test_api_obsolete_dataset_already_obsolete(self):
#         """ DATASET (CORE): Obsoleting dataset which is already obsolete """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#
#     @raises(NotADataset)
#     def test_api_obsolete_dataset_specify_file(self):
#         """ DATASET (CORE): Obsoleting file using dataset obsoletion core api """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         obsolete_dataset(self.scope_misc, lfn, self.user)
#
#     # Error Handling: Associate files to a dataset
#
#     @raises(NoPermissions)
#     def test_api_adds_file_from_dataset_not_owner(self):
#         """ DATASET (CORE): Non owner adds file to a dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user2, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user2, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#
#     @raises(NoPermissions)
#     def test_api_delete_file_from_dataset_not_owner(self):
#         """ DATASET (CORE): Non owner deletes file from a dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user2, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user2, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user2)
#         delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#
#     @raises(DatasetIsMonotonic)
#     def test_api_delete_file_from_monotonic_dataset(self):
#         """ DATASET (CORE): Delete a file from a dataset that is monotonic """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=True)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#         delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#
#     @raises(NameNotFound)
#     def test_api_add_invalid_file_to_dataset(self):
#         """ DATASET (CORE): Assign invalid file to a valid dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         invalid_file = (self.scope_misc, 'some_invalid_file')
#         add_files_to_dataset([invalid_file, ], self.scope_misc, dsn, self.user)
#
#     @raises(FileNotFound)
#     def test_api_delete_non_existant_file_from_dataset(self):
#         """ DATASET (CORE): Delete non existant file from a dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = str(uuid())
#         delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#
#     @raises(FileNotFound)
#     def test_api_delete_non_registered_file_from_dataset(self):
#         """ DATASET (CORE): Delete a file that exists from a dataset, but is not registered to that dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
#
#     @raises(DatasetNotFound)
#     def test_api_add_valid_file_to_invalid_dataset(self):
#         """ DATASET (CORE): Assign valid file to a invalid dataset """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(NotADataset)
#     def test_api_add_valid_file_to_valid_file(self):
#         """ DATASET (CORE): Adding a file to another file """
#         lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, lfn2, self.user)
#
#     # Error Handling: List files in dataset
#
#     @raises(DatasetNotFound)
#     def test_api_list_files_in_dataset_invalid_dataset(self):
#         """ DATASET (CORE): List files in dataset using an invalid dataset name """
#         list_files_in_dataset(self.scope_misc, self.invalid_dsn)
#
#     @raises(ScopeNotFound)
#     def test_api_list_files_in_dataset_invalid_scope(self):
#         """ DATASET (CORE): List files in dataset using an invalid scope name """
#         list_files_in_dataset(self.invalid_scope, self.invalid_dsn)
#
#     # Error Handling: Get dataset metadata
#
#     @raises(DatasetNotFound)
#     def test_api_get_dataset_metadata_invalid_dataset(self):
#         """ DATASET (CORE): Get metadata on invalid dataset """
#         get_dataset_metadata(self.scope_misc, self.invalid_dsn, self.user)
#
#     @raises(ScopeNotFound)
#     def test_api_get_dataset_metadata_invalid_scope(self):
#         """ DATASET (CORE): Get metadata on invalid scope """
#         get_dataset_metadata(self.invalid_scope, self.invalid_dsn, self.user)
#
#     # Error Handling: Dataset registration
#
#     @raises(DatasetAlreadyExists)
#     def test_api_bulk_register_datasets_duplicate_exists(self):
#         """ DATASET (CORE): Bulk register duplicate datasets without duplicate ignore option """
#         tmp_scope = 'tmp_scope2'
#         try:
#             add_scope(tmp_scope, self.user)
#         except Duplicate:
#             pass  # Scope already exists, no need to create it
#         dsn = str(uuid())
#         dsn2 = str(uuid())
#         register_dataset(tmp_scope, dsn2, self.user)
#         bulk_register_datasets(tmp_scope, [dsn, dsn2], self.user, skipExisting=False)
#
#     @raises(AccountNotFound)
#     def test_api_register_dataset_invalid_user(self):
#         """ DATASET (CORE): Register dataset with invalid account name """
#         dsn = str(uuid())
#         register_dataset(self.scope_misc, dsn, self.invalid_user)
#
#     @raises(ScopeNotFound)
#     def test_api_register_dataset_invalid_scope(self):
#         """ DATASET (CORE): Register dataset with scope that does not exist """
#         dsn = str(uuid())
#         register_dataset(self.invalid_scope, dsn, self.user)
#
#     @raises(DatasetAlreadyExists)
#     def test_api_register_duplicate_dataset(self):
#         """ DATASET (CORE): Register a dataset with the same scope and name as another """
#         dsn = str(uuid())
#         self.to_clean_datasets.append(dsn)
#         register_dataset(self.scope_misc, dsn, self.user)
#         register_dataset(self.scope_misc, dsn, self.user)
#
#     @raises(FileAlreadyExists)
#     def test_api_register_clashing_dsn_lfn(self):
#         """ DATASET (CORE): Register a dataset with the same scope and name as an existing file """
#         label = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         self.to_clean_datasets.append(label)
#         register_dataset(self.scope_misc, label, self.user)
#
#     @raises(InputValidationError)
#     def xtest_api_register_dsn_invalid_monotonic_option(self):
#         """ DATASET (CORE): Register a dataset with a wrong monotonic option """
#         dsn = str(uuid())
#         self.to_clean_datasets.append(dsn)
#         register_dataset(self.scope_misc, dsn, self.user, monotonic='yes')
#
#     # Error Handling: Change dataset owner
#
#     @raises(NotADataset)
#     def test_api_change_dataset_owner_specify_file_instead(self):
#         """ DATASET (CORE): Change the owner of a dataset by specifying a file name instead """
#         label = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
#         change_dataset_owner(self.scope_misc, label, self.user, self.user2)
#
#     @raises(AccountNotFound)
#     def test_api_change_dataset_owner_invalid_new_account(self):
#         """ DATASET (CORE): Change the owner of a dataset to a new invalid account """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_dataset_owner(self.scope_misc, dsn, self.user, self.invalid_user)
#
#     @raises(AccountNotFound)
#     def test_api_change_dataset_owner_invalid_old_account(self):
#         """ DATASET (CORE): Change dataset owner by providing invalid account for current owner """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_dataset_owner(self.scope_misc, dsn, self.invalid_user, self.user2)
#
#     @raises(NoPermissions)
#     def test_api_change_dataset_owner_account_not_owner(self):
#         """ DATASET (CORE): Change dataset owner by providing as current owner a valid account that is not the current owner """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_dataset_owner(self.scope_misc, dsn, self.user2, self.user3)
#
#     @raises(ScopeNotFound)
#     def test_api_change_dataset_owner_invalid_scope(self):
#         """ DATASET (CORE): Change dataset in an invalid scope """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         change_dataset_owner(self.invalid_scope, dsn, self.user, self.user2)
#
#     @raises(DatasetNotFound)
#     def test_api_change_dataset_owner_invalid_dsn(self):
#         """ DATASET (CORE): Change the owner of a non existing dataset in a scope """
#         change_dataset_owner(self.scope_misc, self.invalid_dsn, self.user, self.user2)
#
#     @raises(DatasetObsolete)
#     def test_api_change_owner_of_obsolete_dataset(self):
#         """ DATASET (CORE): Change the owner of an obsolete dataset """
#         dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#         obsolete_dataset(self.scope_misc, dsn, self.user)
#         change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)


class xTestDataset_REST():

    def setUp(self):
        build_database(echo=False)
        self.user = 'dataset_user'
        self.user2 = 'user_two'
        self.user_type = 'user'
        self.invalid_user = 'invalid_user'
        try:
            add_account(self.user, self.user_type)
            add_identity('ddmlab2', 'userpass', password='secret')
            add_account_identity('ddmlab2', 'userpass', self.user)
        except Duplicate:
            pass  # Account already exists, no need to create it
        try:
            add_account(self.user2, self.user_type)
            add_identity('ddmlab3', 'userpass', password='secret')
            add_account_identity('ddmlab3', 'userpass', self.user2)
        except Duplicate:
            pass  # Account already exists, no need to create it
        self.scope_misc = 'misc_3'
        try:
            add_scope(self.scope_misc, self.user)
        except Duplicate:
            pass  # Scope already exists, no need to create it
        self.invalid_scope = 'what_scope'
        self.invalid_dsn = 'Sinnerman_where_are_you_going_to_run_to'
        self.to_clean_datasets = []
        self.to_clean_files = []

    def tearDown(self):
        for dsn in self.to_clean_datasets:
            unregister_dataset(self.scope_misc, dsn, self.user)
        for lfn in self.to_clean_files:
            unregister_file(self.scope_misc, lfn, self.user)

    # Register datasets

    def test_register_dataset_success(self):
        """ DATASET (REST): send a POST to create a new dataset """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), True)

    def test_register_dataset_monotonic(self):
        """ DATASET (REST): send a POST to create a monotonic dataset """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'dsn': dsn, 'monotonic': True})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), True)
        assert_equal(is_dataset_monotonic(self.scope_misc, dsn, self.user), True)

    def test_register_dataset_non_monotonic(self):
        """ DATASET (REST): send a POST to create a non monotonic dataset """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'dsn': dsn, 'monotonic': False})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), True)
        assert_equal(is_dataset_monotonic(self.scope_misc, dsn, self.user), False)

    # Check if dataset exists

    def xtest_dataset_exists_search_non_obsolete_implicit(self):
        """ DATASET (REST): send a GET to check if a dataset exists, implicitely only search non obsolete datasets """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'True')
        assert_equal(ret.status, 200)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)

    def xtest_dataset_exists_search_all_datasets_explicit(self):
        """ DATASET (REST): send a GET to check if a dataset exists, explicitely ask for a complete search inlcluding obsoleting datasets """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=all' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=all' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'True')
        assert_equal(ret.status, 200)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=all' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'True')
        assert_equal(ret.status, 200)

    def xtest_dataset_exists_exclude_obsolete(self):
        """ DATASET (REST): send a GET to check if a dataset exists, explicitely exclude obsolete datasets """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=current' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=current' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'True')
        assert_equal(ret.status, 200)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=current' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)

    def xtest_dataset_exists_obsolete_only(self):
        """ DATASET (REST): send a GET to check if a dataset exists, explicitely ask for obsolete search only"""
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=obsolete' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.status, 201)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=obsolete' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'False')
        assert_equal(ret.status, 200)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=obsolete' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'True')
        assert_equal(ret.status, 200)

    # Obsolete datasets

    def xtest_obsolete_dataset(self):
        """ DATASET (REST): send a DELETE to obsolete a dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        assert_equal(is_dataset_obsolete(self.scope_misc, dsn, self.user), False)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).delete('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.status, 200)
        assert_equal(is_dataset_obsolete(self.scope_misc, dsn, self.user), True)

    # Change owner

    def xtest_change_owner_of_dataset(self):
        """ DATASET (REST) send a PUT to change a dataset's owner  """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.scope_misc, dsn, self.user2), headers=headers, expect_errors=True)
        assert_equal(ret.status, 200)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user2)

    # Error Handling: Registering datasets

    def test_register_duplicate_dataset(self):
        """ DATASET (REST): send a POST to create a dataset with an existing name in the same scope """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.normal_body, 'DatasetAlreadyExists: Dataset with same name (%s) already exists in scope (%s)' % (dsn, self.scope_misc))
        assert_equal(ret.status, 409)

    def test_register_duplicate_dataset_with_file(self):
        """ DATASET (REST): send a POST to create a dataset with an existing name as a file in the same scope """
        dsn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        data = dumps({'dsn': dsn})
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.normal_body, 'FileAlreadyExists: File with same name (%s) already exists in scope (%s)' % (dsn, self.scope_misc))
        assert_equal(ret.status, 409)

    def test_register_scope_not_found(self):
        """ DATASET (REST) send a POST to create a dataset in scope that does not exist """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'dsn': dsn})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.invalid_scope), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.normal_body, "ScopeNotFound: Scope '%s' does not exist" % self.invalid_scope)
        assert_equal(ret.status, 404)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), False)

# Shouldn't be possible anymore because the server gets the account name from the token. So the a wrong account name cannot be send a this point.
#    def test_register_invalid_account(self):
#        """ DATASET (REST) send a POST to create a dataset with an account that does not exist """
#        dsn = str(uuid())
#        self.to_clean_datasets.append(dsn)
#        mw = []
#        token = get_auth_token(self.user, 'ddmlab2', 'secret')
#        headers = {'Rucio-Account': self.invalid_user, 'Rucio-Auth-Token': str(token)}
#        data = dumps({'datasetName': dsn})
#        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
#        assert_equal(ret.normal_body, "AccountNotFound: Account '%s' does not exist" % self.invalid_user)
#        assert_equal(ret.status, 404)
#        assert_equal(does_dataset_exist(self.scope_misc, dsn, self.user), False)

    def test_register_dataset_input_error_type(self):
        """ DATASET (REST): send a POST to create a dataset specifying an invalid type """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps({'dsn': dsn, 'monotonic': 'very_large'})
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)
        assert_equal(ret.normal_body, "InputValidationError: Monotonic option needs to be a boolean value")
        assert_equal(ret.status, 400)
        assert_equal(does_dataset_exist(self.scope_misc, dsn), False)

    def test_register_non_json_body(self):
        """ DATASET (REST): send a POST with a non json body"""
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = {'dsn': 'dataset'}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)

        assert_equal(ret.header('ExceptionClass'), 'ValueError')
        assert_equal(ret.normal_body, 'ValueError: cannot decode json parameter dictionary')
        assert_equal(ret.status, 400)

    def test_register_not_json_dict(self):
        """ DATASET (REST): send a POST with a non dictionary json body"""
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        data = dumps(('dsn', 'dataset'))
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).post('/%s' % (self.scope_misc), headers=headers, params=data, expect_errors=True)

        assert_equal(ret.header('ExceptionClass'), 'TypeError')
        assert_equal(ret.normal_body, "TypeError: body must be a json dictionary")
        assert_equal(ret.status, 400)

    # Error Handling: Check if dataset exists

    def xtest_register_invalid_search_type(self):
        """ DATASET (REST): send a GET to check if dataset exists by sending an invalid search type"""
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).get('/%s/%s?searchType=everything' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, 'InputValidationError: search type parameter is not properly defined')
        assert_equal(ret.status, 400)

    # Error Handling: Obsoleting datasets

    def xtest_obsolete_dataset_scope_does_not_exist(self):
        """ DATASET (REST): send a DELETE to obsolete a dataset with a scope that does not exist"""
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Account': self.user, 'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).delete('/%s/%s' % (self.invalid_scope, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "ScopeNotFound: Scope '%s' does not exist" % self.invalid_scope)
        assert_equal(ret.status, 404)

    def xtest_obsolete_dataset_does_not_exist(self):
        """ DATASET (REST): send a DELETE to obsolete a dataset that does not exist """
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).delete('/%s/%s' % (self.scope_misc, self.invalid_dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "DatasetNotFound: Target dataset '%s' in scope '%s' does not exist." % (self.invalid_dsn, self.scope_misc))
        assert_equal(ret.status, 404)

    def xtest_obsolete_dataset_which_is_actually_a_file(self):
        """ DATASET (REST): send a DELETE to obsolete a dataset that is actually a file """
        dsn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).delete('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "NotADataset: Specified dataset '%s' in scope '%s' is actually a file" % (dsn, self.scope_misc))
        assert_equal(ret.status, 404)
        assert_equal(is_file_obsolete(self.scope_misc, dsn, self.user), False)

    def xtest_obsolete_dataset_which_is_already_obsolete(self):
        """ DATASET (REST) send a DELETE to obsolete a dataset that is already obsolete """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).delete('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "DatasetObsolete: Dataset '%s' in scope '%s' already obsolete" % (dsn, self.scope_misc))
        assert_equal(ret.status, 404)

    # Change owner of dataset

    def xtest_change_owner_of_dataset_no_new_account(self):
        """ DATASET (REST) send a PUT to change dataset's owner without specifying owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "InputValidationError: search type parameter is not properly defined")
        assert_equal(ret.status, 400)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)

    def xtest_change_owner_of_dataset_to_invalid_new_account(self):
        """ DATASET (REST) send a PUT to change dataset's owner by specifying invalid new owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.scope_misc, dsn, self.invalid_user), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "AccountNotFound: Account (%s) does not exist" % self.invalid_user)
        assert_equal(ret.status, 404)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)

    def xtest_change_owner_of_dataset_wrong_old_account(self):
        """ DATASET (REST) send a PUT to change dataset's owner by specifying the wrong old owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user2, 'ddmlab3', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.scope_misc, dsn, self.user2), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "NoPermissions: Specified account (%s) is not the owner" % self.user2)
        assert_equal(ret.status, 401)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)

# Shouldn't be possible anymore because the server gets the account from the token.
#    def test_change_owner_of_dataset_invalid_account(self):
#        """ DATASET (REST) send a PUT to change dataset's owner by specifying invalid old owner """
#        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
#        mw = []
#        token = get_auth_token(self.user, 'ddmlab2', 'secret')
#        headers = {'new_account': self.user2, 'Rucio-Account': self.invalid_user, 'Rucio-Auth-Token': str(token)}
#        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s' % (self.scope_misc, dsn), headers=headers, expect_errors=True)
#        assert_equal(ret.normal_body, "AccountNotFound: Account (%s) does not exist" % self.invalid_user)
#        assert_equal(ret.status, 404)
#        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)

    def xtest_change_owner_of_dataset_invalid_scope(self):
        """ DATASET (REST) send a PUT to change dataset's owner by specifying invalid scope """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.invalid_scope, dsn, self.user2), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "ScopeNotFound: Scope (%s) does not exist" % self.invalid_scope)
        assert_equal(ret.status, 404)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)

    def xtest_change_owner_of_dataset_invalid_dsn(self):
        """ DATASET (REST) send a PUT to change dataset's owner by specifying invalid dataset name """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.scope_misc, self.invalid_dsn, self.user2), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "DatasetNotFound: Dataset (%s) does not exist" % self.invalid_dsn)
        assert_equal(ret.status, 404)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)

    def xtest_change_owner_of_dataset_use_filename(self):
        """ DATASET (REST) send a PUT to change dataset's owner by specifying a filename instead """
        dsn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.scope_misc, dsn, self.user2), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "NotADataset: Specified dsn (%s) in scope (%s) is actually a file" % (dsn, self.scope_misc))
        assert_equal(ret.status, 404)

    def xtest_change_owner_of_dataset_obsolete_dataset(self):
        """ DATASET (REST) send a PUT to change an obsolete dataset's owner  """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        mw = []
        token = get_auth_token(self.user, 'ddmlab2', 'secret')
        headers = {'Rucio-Auth-Token': str(token)}
        ret = TestApp(dataset_web_app.wsgifunc(*mw)).put('/%s/%s?newAccount=%s' % (self.scope_misc, dsn, self.user2), headers=headers, expect_errors=True)
        assert_equal(ret.normal_body, "DatasetObsolete: Dataset (%s) in scope (%s) is obsolete" % (dsn, self.scope_misc))
        assert_equal(ret.status, 404)


class xTestDatasetClient():
    def setUp(self):
        build_database(echo=False)
        create_root_account()
        creds = {'username': 'ddmlab', 'password': 'secret'}
        self.dclient = DatasetClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)
        self.aclient = AccountClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)
        self.sclient = ScopeClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

    def tearDown(self):
        destroy_database(echo=False)

    def test_add_dataset(self):
        """ DATASET (CLIENTS): add a new dataset."""
        account = 'root'
        scope = str(uuid())[0:8]
        dataset = str(uuid())[0:8]
        self.sclient.add_scope(account, scope)
        ret = self.dclient.add_dataset(scope, dataset)
        assert_true(ret)

    @raises(ScopeNotFound)
    def test_add_dataset_no_scope(self):
        """ DATASET (CLIENTS): add a new dataset for a non existing scope."""
        scope = str(uuid())
        dataset = str(uuid())
        self.dclient.add_dataset(scope, dataset)

    @raises(DatasetAlreadyExists)
    def test_add_dataset_already_exists(self):
        """ DATASET (CLIENTS): add a dataset that already exists."""
        account = 'root'
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.add_dataset(scope, dataset)

    def xtest_obsolete_dataset(self):
        """ DATASET (CLIENTS): obsolete a dataset."""
        account = 'root'
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.obsolete_dataset(scope, dataset)

    @raises(ScopeNotFound)
    def xtest_obsolete_dataset_wrong_scope(self):
        """ DATASET (CLIENTS): obsolete a dataset with wrong scope."""
        account = 'root'
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.obsolete_dataset('wrong_scope', dataset)

    @raises(DatasetObsolete)
    def xtest_obsolete_dataset_already_obsoleted(self):
        """ DATASET (CLIENTS): obsolete an already obsoleted dataset."""
        account = 'root'
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.obsolete_dataset(scope, dataset)
        self.dclient.obsolete_dataset(scope, dataset)

    @raises(DatasetNotFound)
    def xtest_obsolete_dataset_doesnt_exist(self):
        """ DATASET (CLIENTS): obsolete an non existing dataset."""
        account = 'root'
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.obsolete_dataset(scope, 'wrong_dataset')

    def xtest_change_dataset_owner(self):
        """ DATASET (CLIENTS): change the owner of a dataset."""
        account = 'root'
        new_account = uuid()
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.aclient.create_account(new_account, 'user')
        self.dclient.change_dataset_owner(scope, dataset, new_account)

    @raises(ScopeNotFound)
    def xtest_change_dataset_owner_wrong_scope(self):
        """ DATASET (CLIENTS): change the owner of a dataset with wrong scope."""
        account = 'root'
        new_account = uuid()
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.aclient.create_account(new_account, 'user')
        self.dclient.change_dataset_owner('wrong_scope', dataset, new_account)

    @raises(DatasetObsolete)
    def xtest_change_obsolete_dataset(self):
        """ DATASET (CLIENTS): change the owner of an obsolete dataset."""
        account = 'root'
        new_account = uuid()
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.obsolete_dataset(scope, dataset)
        self.aclient.create_account(new_account, 'user')
        self.dclient.change_dataset_owner(scope, dataset, new_account)

    @raises(DatasetNotFound)
    def xtest_change_dataset_no_dataset(self):
        """ DATASET (CLIENTS): change the owner of a non existing dataset."""
        account = 'root'
        new_account = uuid()
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope(account, scope)
        self.dclient.add_dataset(scope, dataset)
        self.aclient.create_account(new_account, 'user')
        self.dclient.change_dataset_owner(scope, 'wrong_dataset', new_account)

    def xtest_dataset_exists(self):
        """ DATASET (CLIENTS): check if dataset exists."""
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope('root', scope)
        self.dclient.add_dataset(scope, dataset)
        ret = self.dclient.dataset_exists(scope, dataset)
        assert_true(ret)

    def xtest_dataset_exists_current(self):
        """ DATASET (CLIENTS): check if current dataset exists."""
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope('root', scope)
        self.dclient.add_dataset(scope, dataset)
        ret = self.dclient.dataset_exists(scope, dataset, searchType='current')
        assert_true(ret)

    def xtest_dataset_exists_obsolete(self):
        """ DATASET (CLIENTS): check if obsolete dataset exists."""
        scope = uuid()
        dataset = uuid()
        self.sclient.add_scope('root', scope)
        self.dclient.add_dataset(scope, dataset)
        self.dclient.obsolete_dataset(scope, dataset)
        ret = self.dclient.dataset_exists(scope, dataset, searchType='obsolete')
        assert_true(ret)

    def xtest_dataset_exists_all(self):
        """ DATASET (CLIENTS): check different searchTypes for dataset exists."""
        scope = uuid()
        dataset1 = uuid()
        dataset2 = uuid()
        self.sclient.add_scope('root', scope)
        self.dclient.add_dataset(scope, dataset1)
        self.dclient.add_dataset(scope, dataset2)
        self.dclient.obsolete_dataset(scope, dataset1)
        ret = self.dclient.dataset_exists(scope, dataset1)
        assert_false(ret)
        ret = self.dclient.dataset_exists(scope, dataset2, searchType='all')
        assert_true(ret)
