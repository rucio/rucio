# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas,  <angelos.molfetas@cern.ch>, 2012

from nose.tools import *
from sqlalchemy import create_engine
from uuid import uuid4 as uuid

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.inode import add_files_to_dataset, build_inode_list, bulk_register_datasets, bulk_register_files, change_dataset_owner, does_dataset_exist
from rucio.core.inode import delete_files_from_dataset, get_dataset_metadata, get_dataset_owner, list_datasets
from rucio.core.inode import is_dataset_monotonic, is_dataset_obsolete, list_files_in_dataset, obsolete_dataset, obsolete_file, register_file
from rucio.core.inode import register_dataset, unregister_dataset, unregister_file
from rucio.core.scope import add_scope, bulk_add_scopes, check_scope
from rucio.db import models1 as models
from rucio.db.session import build_database
from rucio.tests.common import create_accounts, create_tmp_dataset, create_tmp_file


class TestDataset:
    def setUp(self):
        build_database()
        self.user = 'test_user'
        self.user2 = 'another_usr'
        self.user3 = 'one_more_usr'
        self.user_type = 'user'
        self.scope_misc = 'misc'
        self.invalid_user = 'invalid_user'
        self.invalid_scope = 'invalid_scope'
        self.invalid_dsn = 'invalid_dataset'
        self.to_clean_files = []  # files that eventually need to be cleaned
        self.to_clean_datasets = []  # datasetss that eventually need to be cleaned
        create_accounts([self.user, self.user2, self.user3], self.user_type)
        try:
            add_scope(self.scope_misc, self.user)
        except exception.Duplicate:
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
        assert_equal(does_dataset_exist(self.scope_misc, dsn, self.user), True)  # Dataset exists
        assert_equal(does_dataset_exist(self.scope_misc, self.invalid_dsn, self.user), False)  # Invalid dataset does not exist
        # Unregister dataset
        unregister_dataset(self.scope_misc, dsn, self.user)
        assert_equal(does_dataset_exist(self.user, self.scope_misc, dsn), False)  # Deleted dataset does not exist anymore

    def test_api_bulk_register_datasets(self):
        """ DATASET (CORE): Bulk register datasets """
        tmp_scope = 'tmp_scope'
        try:
            add_scope(tmp_scope, self.user)
        except exception.Duplicate:
            pass  # Scope already exists, no need to create it
        dsn = str(uuid())
        dsn2 = str(uuid())
        dsn3 = str(uuid())
        bulk_register_datasets(tmp_scope, [dsn, dsn2], self.user, skipExisting=True)
        assert_equal(set(list_datasets(self.user, tmp_scope, "%")), set([dsn, dsn2]))
        bulk_register_datasets(tmp_scope, [dsn, dsn2, dsn3], self.user, skipExisting=True)
        assert_equal(set(list_datasets(self.user, tmp_scope, "%")), set([dsn, dsn2, dsn3]))
        self.to_clean_datasets.extend((dsn, dsn2, dsn3))

    def test_api_list_datasets(self):
        """ DATASET (CORE): List datasets in multple scopes """
        self.clean_files_and_datasets()
        # Test single scope
        assert_equal(list_datasets(self.user, self.scopes_mc[0], self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Single scope, single dataset
        assert_equal(list_datasets(self.user, self.scopes_data[0], self.dataset_data_pattern), self.test_data_dsts)  # Single scope, wildcard dst pattern
        assert_equal(list_datasets(self.user, self.scopes_data[0], "*"), self.test_data_dsts)  # Single scope, all dataset (*)
        assert_equal(list_datasets(self.user, self.scopes_data[0], None), self.test_data_dsts)  # Single scope, all dataset (None)
        # Test wildcard in scopes
        assert_equal(list_datasets(self.user, self.scope_mc_pattern, self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Wildcard scopes, single dataset
        assert_equal(list_datasets(self.user, self.scope_mc_pattern, self.dataset_mc_pattern), self.test_mc_dsts)  # Wildcard scope, wildcard dataset
        assert_equal(list_datasets(self.user, self.scope_mc_pattern, "*"), self.test_mc_dsts)  # Wildcard scope, all dataset (*)
        assert_equal(list_datasets(self.user, self.scope_mc_pattern, None), self.test_mc_dsts)  # Wildcard scope, all dataset (None)
        # Test all scopes
        assert_equal(list_datasets(self.user, "*", self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # All scopes, single dataset
        assert_equal(list_datasets(self.user, "*", self.dataset_mc_pattern), self.test_mc_dsts)  # All scopes, wildcard dataset

    # DATASET OWNER

    def test_api_change_owner_check_dataset_metadata(self):
        """ DATASET (CORE): Change the owner of a dataset, get metadata on dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        dst_metadata = {'owner': self.user, 'obsolete': False, 'monotonic': False}
        assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
        dst_metadata['owner'] = self.user2
        change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)
        assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user2), dst_metadata)

    def test_api_change_owner_get_dataset_owner(self):
        """ DATASET (CORE): Change the owner of a dataset, get the owner of the dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user), self.user)
        change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)
        assert_equal(get_dataset_owner(self.scope_misc, dsn, self.user2), self.user2)

    # ADD FILES AND DATASETS TO DATASETS

    def test_api_add_and_delete_files_to_dataset(self):
        """ DATASET (CORE): Add and remove a file to a dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        dsn2 = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [(self.scope_misc, lfn), ])
        delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [])
        assert_equal(list_files_in_dataset(self.scope_misc, dsn2, self.user), [])

    def test_api_add_multiple_files_to_dataset(self):
        """ DATASET (CORE): Add and remove multiple files to a dataset """
        lfn = []
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        file_list = build_inode_list(self.scope_misc, self.test_interesting_files)
        add_files_to_dataset(file_list, self.scope_misc, dsn, self.user)
        assert_equal(set(list_files_in_dataset(self.scope_misc, dsn, self.user)), set(file_list))
        delete_files_from_dataset(file_list, self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [])

    def test_api_add_dataset_to_a_dataset(self):
        """ DATASET (CORE): Add a dataset to another dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        file_list = build_inode_list(self.scope_misc, self.test_interesting_files)
        add_files_to_dataset(file_list, self.scope_misc, dsn, self.user)
        dsn2 = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        add_files_to_dataset([dsn, ], self.scope_misc, dsn2, self.user, self.scope_misc)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn2, self.user), list_files_in_dataset(self.scope_misc, dsn, self.user))

    # Monotonic datasets and obsoleting datasets

    def test_api_create_monotonic_and_non_monotonic_dataset(self):
        """ DATASET (CORE): Create monotonic dataset and check metadata """
        dsn = str(uuid())
        register_dataset(self.scope_misc, dsn, self.user, monotonic=True)
        dst_metadata = {'owner': self.user, 'obsolete': False, 'monotonic': True}
        assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
        unregister_dataset(self.scope_misc, dsn, self.user)
        dsn = str(uuid())
        register_dataset(self.scope_misc, dsn, self.user, monotonic=False)
        dst_metadata = {'owner': self.user, 'obsolete': False, 'monotonic': False}
        assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
        unregister_dataset(self.scope_misc, dsn, self.user)

    def test_api_delete_file_from_non_monotonic_dataset(self):
        """ DATASET (CORE): Delete a file from a dataset that is not monotonic """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=False)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [(self.scope_misc, lfn), ])
        delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [])

    def test_api_check_if_dataset_is_monotonic(self):
        """ DATASET (CORE): Check whether dataset is monotonic """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=True)
        assert_equal(is_dataset_monotonic(self.scope_misc, dsn, self.user), True)
        dsn2 = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=False)
        assert_equal(is_dataset_monotonic(self.scope_misc, dsn2, self.user), False)

    def test_api_obsolete_dataset_and_list(self):
        """ DATASET (CORE): List obsolete dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        assert_equal(list_datasets(self.user, self.scope_misc, dsn), [dsn])
        obsolete_dataset(self.scope_misc, dsn, self.user)
        assert_equal(list_datasets(self.user, self.scope_misc, dsn), [])

    def test_api_obsolete_dataset_and_list(self):
        """ DATASET (CORE): Get obsolute status of a dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        assert_equal(is_dataset_obsolete(self.scope_misc, dsn, self.user), False)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        assert_equal(is_dataset_obsolete(self.scope_misc, dsn, self.user), True)

    def test_api_obsolete_dataset_and_list_files(self):
        """ DATASET (CORE): List files in obsolete dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([lfn, ], self.scope_misc, dsn, self.user, self.scope_misc)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [(self.scope_misc, lfn), ])
        obsolete_dataset(self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [])

    def test_api_obsolete_file_and_list_files_in_dataset(self):
        """ DATASET (CORE): Obsolete one of the files in a dataset and list files in dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([lfn, lfn2], self.scope_misc, dsn, self.user, self.scope_misc)
        obsolete_file(self.scope_misc, lfn2, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [(self.scope_misc, lfn), ])

    # Error Handling: Monotonic datasets

    @raises(exception.DatasetNotFound)
    def test_api_check_monotonic_invalid_dataset(self):
        """ DATASET (CORE): Check monotonic state of invalid dataset """
        is_dataset_monotonic(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_check_monotonic_invalid_dataset(self):
        """ DATASET (CORE): Check monotonic state of dataset in invalid scope """
        is_dataset_monotonic(self.invalid_scope, self.invalid_dsn, self.user)

    @raises(exception.NotADataset)
    def test_api_check_monotonic_dataset_is_a_file(self):
        """ DATASET (CORE): Check monotonic state of a file """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        is_dataset_monotonic(self.scope_misc, lfn, self.user)

    # Error Handling: Obsolete datasets and getting dataset obsolete state

    @raises(exception.DatasetNotFound)
    def test_api_check_if_dataset_is_obsolete(self):
        """ DATASET (CORE): Check obsolete state of invalid dataset """
        is_dataset_obsolete(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_check_if_dataset_is_obsolete_invalid_scope(self):
        """ DATASET (CORE): Check obsolete state of dataset with invalid scope """
        is_dataset_obsolete(self.invalid_scope, self.invalid_dsn, self.user)

    @raises(exception.NotADataset)
    def test_api_check_if_dataset_is_obsolete_not_a_dataset(self):
        """ DATASET (CORE): Check obsolete state of file using dataset obsolete query api """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        is_dataset_obsolete(self.scope_misc, lfn, self.user)

    @raises(exception.DatasetNotFound)
    def test_api_obsolete_invalid_dataset(self):
        """ DATASET (CORE): Obsolete invalid dataset """
        obsolete_dataset(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_obsolete_invalid_scope(self):
        """ DATASET (CORE): Obsolete dataset with invalid scope """
        obsolete_dataset(self.invalid_scope, self.invalid_dsn, self.user)

    @raises(exception.DatasetObsolete)
    def test_api_obsolete_dataset_already_obsolete(self):
        """ DATASET (CORE): Obsoleting dataset which is already obsolete """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        obsolete_dataset(self.scope_misc, dsn, self.user)

    @raises(exception.NotADataset)
    def test_api_obsolete_dataset_specify_file(self):
        """ DATASET (CORE): Obsoleting file using dataset obsoletion core api """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        obsolete_dataset(self.scope_misc, lfn, self.user)

    # Error Handling: Associate files to a dataset

    @raises(exception.NoPermissions)
    def test_api_delete_file_from_dataset_not_owner(self):
        """ DATASET (CORE): Non owner adds file from a dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user2, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user2, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)

    @raises(exception.NoPermissions)
    def test_api_delete_file_from_dataset_not_owner(self):
        """ DATASET (CORE): Non owner deletes file from a dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user2, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user2, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user2)
        delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)

    @raises(exception.DatasetIsMonotonic)
    def test_api_delete_file_from_monotonic_dataset(self):
        """ DATASET (CORE): Delete a file from a dataset that is monotonic """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets, monotonic=True)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)
        delete_files_from_dataset([(self.scope_misc, lfn), ], self.scope_misc, dsn, self.user)

    @raises(exception.InodeNotFound)
    def test_api_add_invalid_file_to_dataset(self):
        """ DATASET (CORE): Assign invalid file to a valid dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        invalid_file = (self.scope_misc, 'some_invalid_file')
        add_files_to_dataset([invalid_file, ], self.scope_misc, dsn, self.user)

    @raises(exception.DatasetNotFound)
    def test_api_add_valid_file_to_invalid_dataset(self):
        """ DATASET (CORE): Assign valid file to a invalid dataset """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.NotADataset)
    def test_api_add_valid_file_to_valid_file(self):
        """ DATASET (CORE): Adding a file to another file """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([(self.scope_misc, lfn), ], self.scope_misc, lfn2, self.user)

    # Error Handling: List files in dataset

    @raises(exception.DatasetNotFound)
    def test_api_list_files_in_dataset_invalid_dataset(self):
        """ DATASET (CORE): List files in dataset using an invalid dataset name """
        list_files_in_dataset(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_list_files_in_dataset_invalid_scope(self):
        """ DATASET (CORE): List files in dataset using an invalid scope name """
        list_files_in_dataset(self.invalid_scope, self.invalid_dsn, self.user)

    # Error Handling: Get dataset metadata

    @raises(exception.DatasetNotFound)
    def test_api_get_dataset_metadata_invalid_dataset(self):
        """ DATASET (CORE): Get metadata on invalid dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        get_dataset_metadata(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_get_dataset_metadata_invalid_scope(self):
        """ DATASET (CORE): Get metadata on invalid scope """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        get_dataset_metadata(self.invalid_scope, self.invalid_dsn, self.user)

    # Error Handling: Dataset registration

    @raises(exception.DatasetAlreadyExists)
    def test_api_bulk_register_datasets_duplicate_exists(self):
        """ DATASET (CORE): Bulk register duplicate datasets without duplicate ignore option """
        tmp_scope = 'tmp_scope2'
        try:
            add_scope(tmp_scope, self.user)
        except exception.Duplicate:
            pass  # Scope already exists, no need to create it
        dsn = str(uuid())
        dsn2 = str(uuid())
        register_dataset(tmp_scope, dsn2, self.user)
        bulk_register_datasets(tmp_scope, [dsn, dsn2], self.user, skipExisting=False)

    @raises(exception.AccountNotFound)
    def test_api_register_dataset_invalid_user(self):
        """ DATASET (CORE): Register dataset with invalid account name """
        dsn = str(uuid())
        register_dataset(self.scope_misc, dsn, self.invalid_user)

    @raises(exception.ScopeNotFound)
    def test_api_register_dataset_invalid_scope(self):
        """ DATASET (CORE): Register dataset with scope that does not exist """
        dsn = str(uuid())
        register_dataset(self.invalid_scope, dsn, self.user)

    @raises(exception.DatasetAlreadyExists)
    def test_api_register_duplicate_dataset(self):
        """ DATASET (CORE): Register a dataset with the same scope and name as another """
        dsn = str(uuid())
        self.to_clean_datasets.append(dsn)
        register_dataset(self.scope_misc, dsn, self.user)
        register_dataset(self.scope_misc, dsn, self.user)

    @raises(exception.FileAlreadyExists)
    def test_api_register_clashing_dsn_lfn(self):
        """ DATASET (CORE): Register a dataset with the same scope and name as an existing file """
        label = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        self.to_clean_datasets.append(label)
        register_dataset(self.scope_misc, label, self.user)

    # Error Handling: Change dataset owner

    @raises(exception.NotADataset)
    def test_api_change_dataset_owner_specify_file_instead(self):
        """ DATASET (CORE): Change the owner of a dataset by specifying a file name instead """
        label = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_dataset_owner(self.scope_misc, label, self.user, self.user2)

    @raises(exception.AccountNotFound)
    def test_api_change_dataset_owner_invalid_new_account(self):
        """ DATASET (CORE): Change the owner of a dataset to a new invalid account """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_dataset_owner(self.scope_misc, dsn, self.user, self.invalid_user)

    @raises(exception.AccountNotFound)
    def test_api_change_dataset_owner_invalid_old_account(self):
        """ DATASET (CORE): Change dataset owner by providing invalid account for current owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_dataset_owner(self.scope_misc, dsn, self.invalid_user, self.user2)

    @raises(exception.NoPermissions)
    def test_api_change_dataset_owner_account_not_owner(self):
        """ DATASET (CORE): Change dataset owner by providing as current owner a valid account that is not the current owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_dataset_owner(self.scope_misc, dsn, self.user2, self.user3)

    @raises(exception.ScopeNotFound)
    def test_api_change_dataset_owner_invalid_scope(self):
        """ DATASET (CORE): Change dataset in an invalid scope """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_dataset_owner(self.invalid_scope, dsn, self.user, self.user2)

    @raises(exception.DatasetNotFound)
    def test_api_change_dataset_owner_invalid_dsn(self):
        """ DATASET (CORE): Change the owner of a non existing dataset in a scope """
        change_dataset_owner(self.scope_misc, self.invalid_dsn, self.user, self.user2)

    @raises(exception.DatasetObsolete)
    def test_api_change_owner_of_obsolete_dataset(self):
        """ DATASET (CORE): Change the owner of an obsolete dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)
