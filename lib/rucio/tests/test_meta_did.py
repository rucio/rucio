# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from nose.tools import assert_equal, assert_in, raises

from rucio.client.dataidentifierclient import DataIdentifierClient
from rucio.common.exception import InvalidValueForKey
from rucio.client.metaclient import MetaClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.utils import generate_uuid as uuid


class TestMetaDIDClient():

    def setUp(self):
        self.did_client = DataIdentifierClient()
        self.meta_client = MetaClient()
        self.rse_client = RSEClient()
        self.scope_client = ScopeClient()

    @raises(InvalidValueForKey)
    def test_add_list_meta(self):
        """ META DID (CLIENTS):  Add metadata to a data identifier"""
        # Add a scope
        tmp_scope = 'scope_%s' % uuid()[:22]
        self.scope_client.add_scope('root', tmp_scope)

        # Add a dataset
        tmp_dataset = 'dsn_%s' % uuid()

        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dataset)

        # Add a key
        key = 'key_' + str(uuid())
        self.meta_client.add_key(key=key)

        value = 'value_' + str(uuid())
        self.did_client.set_metadata(scope=tmp_scope, name=tmp_dataset, key=key, value=value)

        meta = self.did_client.get_metadata(scope=tmp_scope, name=tmp_dataset)
        assert_in(key, meta)
        assert_equal(meta[key], value)

        # Add a new key with a value
        key2 = 'key_' + str(uuid())
        value2 = 'value_' + str(uuid())
        self.meta_client.add_key(key=key2)
        self.meta_client.add_value(key=key2, value=value2)

        # Try a add a wrong value
        self.did_client.set_metadata(scope=tmp_scope, name=tmp_dataset, key=key2, value='Nimportnawak')

        #self.did_client.delete_metadata(scope=tmp_scope, name=tmp_dataset, key=key)
