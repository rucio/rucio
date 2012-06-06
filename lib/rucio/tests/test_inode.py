# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas,  <angelos.molfetas@cern.ch>, 2012

from uuid import uuid4 as uuid

from nose.tools import *
from sqlalchemy import create_engine

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.account import add_account
from rucio.core.inode import bulk_register_datasets, does_dataset_exist, get_dataset_metadata, list_datasets, register_dataset, unregister_dataset
from rucio.core.inode import register_file, unregister_file
from rucio.core.inode import change_inode_owner, does_inode_exist, get_inode_metadata, list_inodes
from rucio.core.scope import add_scope, bulk_add_scopes, check_scope
from rucio.db import models1 as models
from rucio.db.models1 import InodeType
from rucio.db.session import build_database, destroy_database
from rucio.tests.common import create_accounts, create_tmp_dataset, create_tmp_file


class TestInode:

    def setUp(self):
        build_database()

        self.user = 'test_user'
        add_account(self.user, 'user')

        self.user2 = 'another_usr'
        add_account(self.user2, 'user')

        self.user3 = 'one_more_usr'
        add_account(self.user3, 'user')

        self.user_type = 'user'
        self.scope_misc = 'misc'
        self.invalid_user = 'invalid_user'
        self.invalid_scope = 'invalid_scope'
        self.invalid_dsn = 'invalid_dataset'
        self.invalid_file = 'invalid_file'
        self.to_clean_files = []  # files that eventually need to be cleaned
        self.to_clean_datasets = []  # datasetss that eventually need to be cleaned

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
        destroy_database()

    def clean_files_and_datasets(self):
        # Clean unwanted datasets from exceptions
        for dst in self.to_clean_datasets:  # Clean left over datasets
            unregister_dataset(self.scope_misc, dst, self.user)
        for lfn in self.to_clean_files:  # Clean left over files
            unregister_file(self.scope_misc, lfn, self.user)

    def test_api_register_query_unregister_dataset(self):
        """ INODE (CORE): Create and query for inodes """
        dsn = str(uuid())
        # Test registering and quering whether datasets exists
        register_dataset(self.scope_misc, dsn, self.user)
        assert_equal(does_inode_exist(self.scope_misc, dsn, self.user), True)  # Dataset inode exists
        assert_equal(does_inode_exist(self.scope_misc, self.invalid_dsn, self.user), False)  # Invalid dataset inode does not exist
        # Unregister dataset
        unregister_dataset(self.scope_misc, dsn, self.user)
        assert_equal(does_inode_exist(self.user, self.scope_misc, dsn), False)  # Deleted dataset inode does not exist anymore
        lfn = str(uuid())
        # Test registering and quering whether file exists
        register_file(self.scope_misc, lfn, self.user)
        assert_equal(does_inode_exist(self.scope_misc, lfn, self.user), True)  # File inode exists
        assert_equal(does_inode_exist(self.scope_misc, self.invalid_file, self.user), False)  # Invalid file inode does not exist
        # Unregister file
        unregister_file(self.scope_misc, lfn, self.user)
        assert_equal(does_inode_exist(self.user, self.scope_misc, lfn), False)  # Deleted file inode does not exist anymore

    def test_api_list_inodes(self):
        """ INODE (CORE): List inodes in multple scopes """
        self.clean_files_and_datasets()
        # Test single scope
        assert_equal(list_inodes(self.user, self.scopes_mc[0], self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Single scope, single dataset
        assert_equal(list_inodes(self.user, self.scopes_data[0], self.dataset_data_pattern), self.test_data_dsts)  # Single scope, wildcard dst pattern
        assert_equal(list_inodes(self.user, self.scopes_data[0], "*"), self.test_data_dsts)  # Single scope, all dataset (*)
        assert_equal(list_inodes(self.user, self.scopes_data[0], None), self.test_data_dsts)  # Single scope, all dataset (None)
        # Test wildcard in scopes
        assert_equal(list_inodes(self.user, self.scope_mc_pattern, self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # Wildcard scopes, single dataset
        assert_equal(list_inodes(self.user, self.scope_mc_pattern, self.dataset_mc_pattern), self.test_mc_dsts)  # Wildcard scope, wildcard dataset
        assert_equal(list_inodes(self.user, self.scope_mc_pattern, "*"), self.test_mc_dsts)  # Wildcard scope, all dataset (*)
        assert_equal(list_inodes(self.user, self.scope_mc_pattern, None), self.test_mc_dsts)  # Wildcard scope, all dataset (None)
        # Test all scopes
        assert_equal(list_inodes(self.user, "*", self.test_mc_dsts[0]), [self.test_mc_dsts[0]])  # All scopes, single dataset
        assert_equal(list_inodes(self.user, "*", self.dataset_mc_pattern), self.test_mc_dsts)  # All scopes, wildcard dataset

    def test_api_change_does_inode_exist_owner(self):
        """ INODE (CORE): Change the owner of an inode, get metadata on inode """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        dst_metadata = {'owner': self.user, 'obsolete': False, 'type': InodeType.DATASET, 'monotonic': False}
        assert_equal(get_inode_metadata(self.scope_misc, dsn, self.user), dst_metadata)
        dst_metadata['owner'] = self.user2
        change_inode_owner(self.scope_misc, dsn, self.user, self.user2)
        assert_equal(get_inode_metadata(self.scope_misc, dsn, self.user2), dst_metadata)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        file_metadata = {'owner': self.user, 'obsolete': False, 'type': InodeType.FILE}
        assert_equal(get_inode_metadata(self.scope_misc, lfn, self.user), file_metadata)
        file_metadata['owner'] = self.user2
        change_inode_owner(self.scope_misc, lfn, self.user, self.user2)
        assert_equal(get_inode_metadata(self.scope_misc, lfn, self.user2), file_metadata)

    def test_api_get_inode_dataset_metadata_invalid_scope(self):
        """ INODE (CORE): Get inode metadata on invalid scope """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        assert_equal(get_inode_metadata(self.invalid_scope, dsn, self.user), None)
        assert_equal(get_inode_metadata(self.invalid_scope, lfn, self.user), None)

    # Error Handling: Get dataset metadata

    @raises(exception.DatasetNotFound)
    def test_api_get_inode_dataset_metadata_invalid_dataset(self):
        """ INODE (CORE): Get metadata on invalid inode """
        get_dataset_metadata(self.scope_misc, self.invalid_dsn, self.user)

    # Error Handling: Change dataset owner

    @raises(exception.AccountNotFound)
    def test_api_change_inode_dataset_owner_invalid_new_account(self):
        """ INODE (CORE): Change the owner of a inode (dataset) to a new invalid account """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_inode_owner(self.scope_misc, dsn, self.user, self.invalid_user)

    @raises(exception.AccountNotFound)
    def test_api_change_inode_file_owner_invalid_new_account(self):
        """ INODE (CORE): Change the owner of a inode (file) to a new invalid account """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_inode_owner(self.scope_misc, lfn, self.user, self.invalid_user)

    @raises(exception.AccountNotFound)
    def test_api_change_inode_dataset_owner_invalid_old_account(self):
        """ INODE (CORE): Change inode (dataset) owner by providing invalid account for current owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_inode_owner(self.scope_misc, dsn, self.invalid_user, self.user2)

    @raises(exception.AccountNotFound)
    def test_api_change_inode_file_owner_invalid_old_account(self):
        """ INODE (CORE): Change file (owner) by providing invalid account for current owner """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_inode_owner(self.scope_misc, lfn, self.invalid_user, self.user2)

    @raises(exception.NoPermissions)
    def test_api_change_inode_dataset_owner_account_not_owner(self):
        """ INODE (CORE): Change inode (dataset) owner by providing as current owner a valid account that is not the current owner """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_inode_owner(self.scope_misc, dsn, self.user2, self.user3)

    @raises(exception.NoPermissions)
    def test_api_change_inode_file_owner_account_not_owner(self):
        """ INODE (CORE): Change inode (file) owner by providing as current owner a valid account that is not the current owner """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        change_inode_owner(self.scope_misc, lfn, self.user2, self.user3)

    @raises(exception.ScopeNotFound)
    def test_api_change_inode_dataset_owner_invalid_scope(self):
        """ INODE (CORE): Change inode (dataset) in an invalid scope """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        change_inode_owner(self.invalid_scope, dsn, self.user, self.user2)

    @raises(exception.ScopeNotFound)
    def test_api_change_inode_file_owner_invalid_scope(self):
        """ INODE (CORE): Change inode (file) in an invalid scope """
        lfn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_files)
        change_inode_owner(self.invalid_scope, lfn, self.user, self.user2)

    @raises(exception.DatasetNotFound)
    def test_api_change_dataset_owner_invalid_dsn(self):
        """ INODE (CORE): Change the owner of a non existing inode in a scope """
        change_inode_owner(self.scope_misc, self.invalid_dsn, self.user, self.user2)
