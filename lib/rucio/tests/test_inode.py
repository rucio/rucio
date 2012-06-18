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
from rucio.core.inode import add_files_to_dataset, bulk_register_datasets, does_dataset_exist, get_dataset_metadata, is_inode_obsolete, list_datasets
from rucio.core.inode import list_files_in_dataset, obsolete_dataset, obsolete_file, obsolete_inode
from rucio.core.inode import register_dataset, register_file, unregister_dataset, unregister_file
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

    # Register and query inodes

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

    # Obsoleting inodes

    def test_api_obsolete_dataset_and_list(self):
        """ INODE (CORE): List inodes which are not obsolete """
        scope_tmp = 'some_scope'
        add_scope(scope_tmp, self.user)
        dsn = create_tmp_dataset(scope_tmp, self.user, self.to_clean_datasets)
        assert_equal(list_inodes(self.user, scope_tmp, dsn), [dsn])
        obsolete_inode(scope_tmp, dsn, self.user)
        assert_equal(list_inodes(self.user, scope_tmp, dsn), [])
        lfn = create_tmp_file(scope_tmp, self.user, self.to_clean_files)
        assert_equal(list_inodes(self.user, scope_tmp, lfn), [lfn])
        obsolete_inode(scope_tmp, lfn, self.user)
        assert_equal(list_inodes(self.user, scope_tmp, lfn), [])

    def test_api_obsoletes_dataset_and_files_and_check_obsolete_status(self):
        """ INODE (CORE): Get obsolete status of an inodes """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        assert_equal(is_inode_obsolete(self.scope_misc, dsn, self.user), False)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        assert_equal(is_inode_obsolete(self.scope_misc, dsn, self.user), True)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        assert_equal(is_inode_obsolete(self.scope_misc, lfn, self.user), False)
        obsolete_file(self.scope_misc, lfn, self.user)
        assert_equal(is_inode_obsolete(self.scope_misc, lfn, self.user), True)
        lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        assert_equal(is_inode_obsolete(self.scope_misc, lfn2, self.user), False)
        obsolete_inode(self.scope_misc, lfn2, self.user)
        assert_equal(is_inode_obsolete(self.scope_misc, lfn2, self.user), True)

    def test_api_obsoletes_dataset_and_files_and_check_obsolete_status(self):
        """ INODE (CORE): List obsolete inodes """
        tmp_scope = 'next scope'
        add_scope(tmp_scope, self.user)
        dsn = create_tmp_dataset(tmp_scope, self.user, self.to_clean_datasets)
        obsolete_dataset(tmp_scope, dsn, self.user)
        lfn = create_tmp_file(tmp_scope, self.user, self.to_clean_files)
        obsolete_file(tmp_scope, lfn, self.user)
        lfn2 = create_tmp_file(tmp_scope, self.user, self.to_clean_files)
        obsolete_inode(tmp_scope, lfn2, self.user)
        dsn2 = create_tmp_dataset(tmp_scope, self.user, self.to_clean_files)
        assert_equal(list_inodes(inodeScope=tmp_scope, accountName=self.user, obsolete=False), [dsn2])
        assert_equal(set(list_inodes(inodeScope=tmp_scope, accountName=self.user, obsolete=True)), set([dsn, lfn, lfn2, dsn2]))

    def test_api_obsolete_dataset_and_list_files(self):
        """ INODE (CORE): List files in dataset, which was obsoleted using the inode obsolete API """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([lfn, ], self.scope_misc, dsn, self.user, self.scope_misc)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [(self.scope_misc, lfn), ])
        obsolete_inode(self.scope_misc, dsn, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [])

    def test_api_obsolete_file_and_list_files_in_dataset(self):
        """ DATASET (CORE): Obsolete one of the files in a dataset using inode obsolete API and list files in dataset """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        lfn2 = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        add_files_to_dataset([lfn, lfn2], self.scope_misc, dsn, self.user, self.scope_misc)
        obsolete_inode(self.scope_misc, lfn2, self.user)
        assert_equal(list_files_in_dataset(self.scope_misc, dsn, self.user), [(self.scope_misc, lfn), ])

   # Error Handling: Obsolete datasets and getting dataset obsolete state

    @raises(exception.InodeNotFound)
    def test_api_check_if_inode_is_obsolete(self):
        """ INODE (CORE): Check obsolete state of invalid inode """
        is_inode_obsolete(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_check_if_dataset_is_obsolete_invalid_scope(self):
        """ INODE (CORE): Check obsolete state of inode with invalid scope """
        is_inode_obsolete(self.invalid_scope, self.invalid_dsn, self.user)

    @raises(exception.InodeNotFound)
    def test_api_obsolete_invalid_inode(self):
        """ INODE (CORE): Obsolete invalid inode """
        obsolete_inode(self.scope_misc, self.invalid_dsn, self.user)

    @raises(exception.ScopeNotFound)
    def test_api_obsolete_node_invalid_scope(self):
        """ INODE (CORE): Obsolete dataset with invalid scope """
        obsolete_inode(self.invalid_scope, self.invalid_dsn, self.user)

    @raises(exception.DatasetObsolete)
    def test_api_obsolete_inode_dataset_already_obsolete(self):
        """ INODE (CORE): Obsoleting dataset which is already obsolete """
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        obsolete_inode(self.scope_misc, dsn, self.user)
        obsolete_inode(self.scope_misc, dsn, self.user)

    @raises(exception.FileObsolete)
    def test_api_obsolete_inode_file_already_obsolete(self):
        """ INODE (CORE): Obsoleting file which is already obsolete """
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        obsolete_inode(self.scope_misc, lfn, self.user)
        obsolete_inode(self.scope_misc, lfn, self.user)

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

    @raises(exception.InodeNotFound)
    def test_api_change_dataset_owner_invalid_dsn(self):
        """ INODE (CORE): Change the owner of a non existing inode in a scope """
        change_inode_owner(self.scope_misc, self.invalid_dsn, self.user, self.user2)

    @raises(exception.FileObsolete)
    def test_api_inode_change_owner_of_obsolete_file(self):
        """ INODE (CORE): Change the owner of an obsolete file using inode change owner API"""
        lfn = create_tmp_file(self.scope_misc, self.user, self.to_clean_files)
        obsolete_file(self.scope_misc, lfn, self.user)
        change_inode_owner(self.scope_misc, lfn, self.user, self.user2)

    @raises(exception.DatasetObsolete)
    def test_api_inode_change_owner_of_obsolete_dataset(self):
        """ FILE (CORE): Change the owner of an obsolete dataset using inode change owner API"""
        dsn = create_tmp_dataset(self.scope_misc, self.user, self.to_clean_datasets)
        obsolete_dataset(self.scope_misc, dsn, self.user)
        change_inode_owner(self.scope_misc, dsn, self.user, self.user2)
