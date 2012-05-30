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
from rucio.core.inode import bulk_register_datasets, change_dataset_owner, check_dataset, get_dataset_metadata, list_datasets
from rucio.core.inode import register_dataset, unregister_dataset
from rucio.core.inode import register_file, unregister_file
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

    def tearDown(self):
        self.clean_files_and_datasets()
        for dst in self.test_mc_dsts:  # Clean mc datasets
            unregister_dataset(self.scopes_mc[0], dst, self.user)
        for dst in self.test_data_dsts:  # Clean data datasets
            unregister_dataset(self.scopes_data[0], dst, self.user)

    def clean_files_and_datasets(self):
        # Clean unwanted datasets from exceptions
        for dst in self.to_clean_datasets:  # Clean left over datasets
            unregister_dataset(self.scope_misc, dst, self.user)
        for lfn in self.to_clean_files:  # Clean left over files
            unregister_file(self.scope_misc, lfn, self.user)

    def test_api_register_query_unregister_dataset(self):
        """ DATASET (CORE): Create and query for datasets """
        dsn = str(uuid())
        # Test registering and quering whether datasets exists
        register_dataset(self.scope_misc, dsn, self.user)
        assert_equal(check_dataset(self.scope_misc, dsn, self.user), True)  # Dataset exists
        assert_equal(check_dataset(self.scope_misc, self.invalid_dsn, self.user), False)  # Invalid dataset does not exist
        # Unregister dataset
        unregister_dataset(self.scope_misc, dsn, self.user)
        assert_equal(check_dataset(self.user, self.scope_misc, dsn), False)  # Deleted dataset does not exist anymore

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
        assert_equal(list_datasets(self.user, '%', '%'), self.test_data_dsts + self.test_mc_dsts)  # List all datasets in all scopes

    def test_api_change_check_dataset_owner(self):
        """ DATASET (CORE): Change the owner of a dataset, get metadata on dataset """
        dsn = str(uuid())
        register_dataset(self.scope_misc, dsn, self.user)
        dst_metadata = {'owner': self.user, 'obsolete': False}
        assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user), dst_metadata)
        dst_metadata['owner'] = self.user2
        change_dataset_owner(self.scope_misc, dsn, self.user, self.user2)
        assert_equal(get_dataset_metadata(self.scope_misc, dsn, self.user2), dst_metadata)
        unregister_dataset(self.scope_misc, dsn, self.user)

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

    @raises(exception.NoPermisions)
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
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_dataset_owner(self.scope_misc, self.invalid_dsn, self.user, self.user2)
