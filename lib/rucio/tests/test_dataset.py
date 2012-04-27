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
from rucio.core.account import add_account
from rucio.core.dataset import create_dataset
from rucio.core.scope import add_scope
from rucio.db import models1 as models
from rucio.db.session import build_database


class TestDataset:
    def setUp(self):
        build_database()
        self.user = 'test_user'
        self.user_type = 'user'
        self.scope = 'tzero'
        self.invalid_user = 'invalid_user'
        self.invalid_scope = 'invalid_scope'
        try:
            add_account(self.user, self.user_type)
        except exception.Duplicate:
            pass  # Account already exists, no need to create it
        try:
            add_scope(self.scope, self.user)
        except exception.Duplicate:
            pass  # Scope already exists, no need to create it

    def tearDown(self):
        pass

    def test_api_create_dataset_success(self):
        """ DATASET: Test dataset creation """
        dsn = str(uuid())
        create_dataset(self.user, self.scope, dsn)

    @raises(exception.AccountNotFound)
    def test_api_create_dataset_invalid_user(self):
        """ DATASET: Create dataset with invalid account name """
        dsn = str(uuid())
        create_dataset(self.invalid_user, self.scope, dsn)

    @raises(exception.ScopeNotFound)
    def test_api_create_dataset_invalid_scope(self):
        """ DATASET: Create dataset with scope that does not exist """
        dsn = str(uuid())
        create_dataset(self.user, self.invalid_scope, dsn)

    @raises(exception.DatasetAlreadyExists)
    def test_api_create_duplicate_dataset(self):
        """ DATASET: Creating a dataset with the same scope and name as another """
        dsn = str(uuid())
        create_dataset(self.user, self.scope, dsn)
        create_dataset(self.user, self.scope, dsn)
