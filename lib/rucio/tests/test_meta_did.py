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

from nose.tools import assert_equal, assert_in  # , assert_raises

from rucio.client.didclient import DIDClient
# from rucio.common.exception import InvalidValueForKey, UnsupportedOperation
from rucio.client.metaclient import MetaClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.utils import generate_uuid as uuid


class TestMetaDIDClient():

    def setup(self):
        self.did_client = DIDClient()
        self.meta_client = MetaClient()
        self.rse_client = RSEClient()
        self.scope_client = ScopeClient()

    def test_add_list_meta(self):
        """ META DID (CLIENTS):  Add metadata to a data identifier"""
        # Add a scope
        tmp_scope = 'mock'

        # Add a dataset
        tmp_dataset = 'dsn_%s' % uuid()

        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dataset)

        # Add a key
        key = 'project'
        value = 'data13_hip'
        self.did_client.set_metadata(scope=tmp_scope, name=tmp_dataset, key=key, value=value)

        meta = self.did_client.get_metadata(scope=tmp_scope, name=tmp_dataset)
        assert_in(key, meta)
        assert_equal(meta[key], value)

        # Add a new key with a value
#         key2 = 'datatype'
#         value2 = 'value_' + str(uuid())
#         self.meta_client.add_key(key=key2, key_type='COLLECTION')
#         self.meta_client.add_value(key=key2, value=value2)
#
#         # Try a add a wrong value
#         with assert_raises(InvalidValueForKey):
#             self.did_client.set_metadata(scope=tmp_scope, name=tmp_dataset, key=key2, value='Nimportnawak')
#
#         # Add a new key with a value
#         key3 = 'key_' + str(uuid())[:20]
#         value3 = 'value_' + str(uuid())
#         self.meta_client.add_key(key=key3, key_type='FILE')
#         self.meta_client.add_value(key=key3, value=value3)
#
#         with assert_raises(UnsupportedOperation):
#             self.did_client.set_metadata(scope=tmp_scope, name=tmp_dataset, key=key3, value=value3)

        # self.did_client.delete_metadata(scope=tmp_scope, name=tmp_dataset, key=key)
