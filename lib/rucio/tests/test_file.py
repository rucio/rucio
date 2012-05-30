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
from rucio.core.inode import bulk_register_files, change_file_owner, check_file, get_file_metadata, list_files, register_file, unregister_file
from rucio.core.inode import register_dataset, unregister_dataset
from rucio.core.scope import add_scope, bulk_add_scopes, check_scope
from rucio.db import models1 as models
from rucio.db.session import build_database
from rucio.tests.common import create_accounts, create_tmp_dataset, create_tmp_file


class TestFile:
    def setUp(self):
        build_database()
        self.user = 'test_user'
        self.user2 = 'another user'
        self.user3 = 'user3'
        self.user_type = 'user'
        self.scope_misc = 'misc'
        self.invalid_user = 'invalid_user'
        self.invalid_scope = 'invalid_scope'
        self.invalid_file = 'invalid_file'
        self.to_clean_files = []  # files that eventually need to be cleaned
        self.to_clean_datasets = []  # datasets that eventually need to be cleaned
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
        self.file_data_prefix = 'data12.'
        self.file_mc_prefix = 'mc12.'
        self.file_data_pattern = self.file_data_prefix + '%'
        self.file_mc_pattern = self.file_mc_prefix + '%'
        self.test_data_files = [self.file_data_prefix + str(i) for i in range(4)]
        self.test_mc_files = [self.file_mc_prefix + str(i) for i in range(4)]
        bulk_register_files(self.scopes_data[0], self.test_data_files, self.user, skipExisting=True)
        bulk_register_files(self.scopes_mc[0], self.test_mc_files, self.user, skipExisting=True)

    def tearDown(self):
        self.clean_files_and_datasets()
        for lfn in self.test_mc_files:  # Clean mc datasets
            unregister_file(self.scopes_mc[0], lfn, self.user)
        for lfn in self.test_data_files:  # Clean data datasets
            unregister_file(self.scopes_data[0], lfn, self.user)

    def clean_files_and_datasets(self):
        # Clean unwanted files and datasets from exceptions
        for lfn in self.to_clean_files:  # Clean left over files
            unregister_file(self.scope_misc, lfn, self.user)
        for dsn in self.to_clean_datasets:  # Clean left over datasets
            unregister_dataset(self.scope_misc, dsn, self.user)

    def test_api_register_query_unregister_file(self):
        """ FILE (CORE): Create and query a file """
        assert_equal(check_file(self.user, self.scope_misc, self.invalid_file), False)  # Invalid file does not exist
        lfn = str(uuid())
        register_file(self.scope_misc, lfn, self.user)
        assert_equal(check_file(self.scope_misc, lfn, self.user), True)  # File should exist
        register_file(self.scopes_data[1], lfn, self.user)  # Register duplicate lfn, but in a different scope
        assert_equal(check_file(self.scopes_data[1], lfn, self.user), True)  # File should exist
        unregister_file(self.scope_misc, lfn, self.user)
        unregister_file(self.scopes_data[1], lfn, self.user)
        assert_equal(check_file(self.scope_misc, lfn, self.user), False)  # Deleted file does not exist anymore
        assert_equal(check_file(self.scopes_data[1], lfn, self.user), False)  # Deleted file does not exist anymore

    def test_api_list_datasets(self):
        """ FILE (CORE): List files in multple scopes """

        self.clean_files_and_datasets()
        # Test single scope
        assert_equal(list_files(self.user, self.scopes_mc[0], self.test_mc_files[0]), [self.test_mc_files[0]])  # Single scope, single file
        assert_equal(list_files(self.user, self.scopes_data[0], self.file_data_pattern), self.test_data_files)  # Single scope, wildcard file pattern
        assert_equal(list_files(self.user, self.scopes_data[0], "*"), self.test_data_files)  # Single scope, all files (*)
        assert_equal(list_files(self.user, self.scopes_data[0], None), self.test_data_files)  # Single scope, all files (None)
        # Test wildcard in scopes
        assert_equal(list_files(self.user, self.scope_mc_pattern, self.test_mc_files[0]), [self.test_mc_files[0]])  # Wildcard scopes, single file
        assert_equal(list_files(self.user, self.scope_mc_pattern, self.file_mc_pattern), self.test_mc_files)  # Wildcard scope, wildcard file
        assert_equal(list_files(self.user, self.scope_mc_pattern, "*"), self.test_mc_files)  # Wildcard scope, all files (*)
        assert_equal(list_files(self.user, self.scope_mc_pattern, None), self.test_mc_files)  # Wildcard scope, all files (None)
        # Test all scopes
        assert_equal(list_files(self.user, "*", self.test_mc_files[0]), [self.test_mc_files[0]])  # All scopes, single file
        assert_equal(list_files(self.user, "*", self.file_mc_pattern), self.test_mc_files)  # All scopes, wildcard files
        assert_equal(list_files(self.user, '%', '%'), self.test_data_files + self.test_mc_files)  # List all datasets in all scopes

    def test_api_change_check_file_owner(self):
        """ FILE (CORE): Change the owner of a file, get metadata on file """
        lfn = str(uuid())
        register_file(self.scope_misc, lfn, self.user)
        file_metadata = {'owner': self.user, 'obsolete': False}
        assert_equal(get_file_metadata(self.scope_misc, lfn, self.user), file_metadata)
        file_metadata['owner'] = self.user2
        change_file_owner(self.scope_misc, lfn, self.user, self.user2)
        assert_equal(get_file_metadata(self.scope_misc, lfn, self.user2), file_metadata)
        unregister_file(self.scope_misc, lfn, self.user)

    # Error Handling: Dataset registration

    @raises(exception.AccountNotFound)
    def test_api_register_dataset_invalid_user(self):
        """ FILE (CORE): Register file with invalid account name """
        lfn = str(uuid())
        register_file(self.scope_misc, lfn, self.invalid_user)

    @raises(exception.ScopeNotFound)
    def test_api_register_dataset_invalid_scope(self):
        """ FILE (CORE): Register file with scope that does not exist """
        lfn = str(uuid())
        register_file(self.invalid_scope, lfn, self.user)

    @raises(exception.FileAlreadyExists)
    def test_api_create_duplicate_dataset(self):
        """ FILE (CORE): Register a file with the same scope and name as another file"""
        lfn = str(uuid())
        self.to_clean_files.append(lfn)
        register_file(self.scope_misc, lfn, self.user)
        register_file(self.scope_misc, lfn, self.user)

    @raises(exception.DatasetAlreadyExists)
    def test_api_create_clashing_dsn_lfn(self):
        """ FILE (CORE): Register a file with the same scope and name as an existing dataset"""
        label = str(uuid())
        self.to_clean_files.append(label)
        self.to_clean_datasets.append(label)
        register_dataset(self.scope_misc, label, self.user)
        register_file(self.scope_misc, label, self.user)

    # Error Handling: Change dataset owner

    @raises(exception.NotAFile)
    def test_api_change_file_owner_specify_file_instead(self):
        """ FILE (CORE): Change the owner of a file by specifying a dataset name instead """
        label = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_file_owner(self.scope_misc, label, self.user, self.user2)

    @raises(exception.AccountNotFound)
    def test_api_change_file_owner_invalid_new_account(self):
        """ FILE (CORE): Change the owner of a file to a new invalid account """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_file_owner(self.scope_misc, lfn, self.user, self.invalid_user)

    @raises(exception.AccountNotFound)
    def test_api_change_file_owner_invalid_old_account(self):
        """ FILE (CORE): Change file owner by providing invalid account for current owner """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_file_owner(self.scope_misc, lfn, self.invalid_user, self.user2)

    @raises(exception.NoPermisions)
    def test_api_change_file_owner_account_not_owner(self):
        """ FILE (CORE): Change file owner by providing as the current owner a valid account that is not the current owner """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_file_owner(self.scope_misc, lfn, self.user2, self.user3)

    @raises(exception.ScopeNotFound)
    def test_api_change_file_owner_invalid_scope(self):
        """ FILE (CORE): Change file in an invalid scope """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_file_owner(self.invalid_scope, lfn, self.user, self.user2)

    @raises(exception.FileNotFound)
    def test_api_change_file_owner_invalid_lfn(self):
        """ FILE (CORE): Change the owner of a non existing file in a scope """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_file_owner(self.scope_misc, self.invalid_file, self.user, self.user2)
