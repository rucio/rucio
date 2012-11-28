# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from nose.tools import assert_equal, assert_raises, assert_in

from rucio.client.accountclient import AccountClient
from rucio.client.dataidentifierclient import DataIdentifierClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import DataIdentifierNotFound
from rucio.common.utils import generate_uuid


class TestIdentifierClients():

    def setup(self):
        self.account_client = AccountClient()
        self.scope_client = ScopeClient()
        self.did_client = DataIdentifierClient()
        self.rse_client = RSEClient()

    def test_exists(self):
        """ DATA IDENTIFIERS (CLIENT): Check if data identifier exists """
        tmp_scope = 'scope_%s' % generate_uuid()
        tmp_file = 'file_%s' % generate_uuid()
        tmp_rse = 'rse_%s' % generate_uuid()

        self.rse_client.add_rse(tmp_rse)
        self.rse_client.add_file_replica(tmp_rse, tmp_scope, tmp_file, 1L, 1L)

        assert_equal(self.did_client.get_did(tmp_scope, tmp_file), {'scope': tmp_scope, 'did': tmp_file, 'type': 'file'})

        with assert_raises(DataIdentifierNotFound):
            self.did_client.get_did('i_dont_exist', 'neither_do_i')

    def test_scope_list(self):
        """ DATA IDENTIFIERS (CLIENT): Add, aggregate, and list data identifiers in a scope """

        # create some dummy data
        self.tmp_accounts = ['account_%s' % generate_uuid() for i in xrange(10)]
        self.tmp_scopes = ['scope_%s' % generate_uuid() for i in xrange(10)]
        self.tmp_rses = ['rse_%s' % generate_uuid() for i in xrange(10)]
        self.tmp_files = ['file_%s' % generate_uuid() for i in xrange(10)]
        self.tmp_datasets = ['dataset_%s' % generate_uuid() for i in xrange(10)]
        self.tmp_containers = ['container_%s' % generate_uuid() for i in xrange(10)]

        # add dummy data to the catalogue
        for i in xrange(10):
            self.account_client.add_account(self.tmp_accounts[i], 'user')
            self.scope_client.add_scope(self.tmp_accounts[i], self.tmp_scopes[i])
            self.rse_client.add_rse(self.tmp_rses[i])
            self.rse_client.add_file_replica(self.tmp_rses[i], self.tmp_scopes[i], self.tmp_files[i], 1L, 1L)

        # put files in datasets
        for i in xrange(10):
            for j in xrange(10):
                files = [{'scope': self.tmp_scopes[j], 'did': self.tmp_files[j]}]
                self.did_client.add_identifier(self.tmp_scopes[i], self.tmp_datasets[j], files)

        # put datasets in containers
        for i in xrange(10):
            for j in xrange(10):
                datasets = [{'scope': self.tmp_scopes[j], 'did': self.tmp_datasets[j]}]
                self.did_client.add_identifier(self.tmp_scopes[i], self.tmp_containers[j], datasets)

        # reverse check if everything is in order
        for i in xrange(10):
            result = self.did_client.scope_list(self.tmp_scopes[i])
            assert_in(result[0]['scope'], self.tmp_scopes[i])

            r_dids = [r['did'] for r in result]
            for j in xrange(10):
                assert_in(self.tmp_files[i], r_dids)
                assert_in(self.tmp_datasets[j], r_dids)
                assert_in(self.tmp_containers[j], r_dids)
