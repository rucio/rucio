# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps, loads

from paste.fixture import TestApp
from nose.tools import assert_equal, assert_true, assert_in, raises, assert_is_instance

from rucio.client.metaclient import MetaClient
from rucio.common.exception import KeyNotFound
from rucio.common.utils import generate_uuid as uuid
from rucio.core.meta import add_key, add_value, list_keys, list_values
from rucio.web.rest.authentication import app as auth_app
from rucio.web.rest.meta import app as meta_app


class TestMetaCoreApi():

    def test_add_key(self):
        """ META (CORE):  Create a new allowed key """
        key = 'key_' + str(uuid())
        add_key(key=key)
        keys = list_keys()
        assert_in(key, keys)

    def test_add_value(self):
        """ META (CORE):  Add a new value to a key """
        key = 'key_' + str(uuid())
        value = 'value_' + str(uuid())
        add_key(key=key)
        add_value(key=key, value=value)
        values = list_values(key=key)
        assert_in(value, values)

    @raises(KeyNotFound)
    def test_add_value_to_bad_key(self):
        """ META (CORE):  Add a new value to a non existing key """
        value = 'value_' + str(uuid())
        add_value(key="Nimportnawak", value=value)


class TestMeta():

    def test_add_key(self):
        """ META (REST): send a POST to create a new allowed key """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        key = 'key_' + str(uuid())

        headers2 = {'Rucio-Auth-Token': str(token)}
        r2 = TestApp(meta_app.wsgifunc(*mw)).post('/' + key, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(meta_app.wsgifunc(*mw)).post('/' + key, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 409)

    def test_list_keys(self):
        """ META (REST): send a GET to list all keys """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Auth-Token': str(token)}
        key = 'key_' + str(uuid())
        r2 = TestApp(meta_app.wsgifunc(*mw)).post('/' + key, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(meta_app.wsgifunc(*mw)).get('/', headers=headers3, expect_errors=True)
        assert_in(key, loads(r3.body))
        assert_equal(r3.status, 200)

    def test_add_value(self):
        """ META (REST): send a POST to create a new value for an allowed key """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)

        token = str(r1.header('Rucio-Auth-Token'))

        key = 'key_' + str(uuid())
        value = 'value_' + str(uuid())

        headers2 = {'Rucio-Auth-Token': str(token)}
        r2 = TestApp(meta_app.wsgifunc(*mw)).post('/' + key, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Auth-Token': str(token)}
        r3 = TestApp(meta_app.wsgifunc(*mw)).post('/' + key + '/' + value, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 201)

        headers4 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r4 = TestApp(meta_app.wsgifunc(*mw)).get('/' + key + '/', headers=headers4, expect_errors=True)
        assert_in(value, loads(r4.body))
        assert_equal(r4.status, 200)


class TestMetaClient():

    def setUp(self):
        self.meta_client = MetaClient()

    def test_add_and_list_keys(self):
        """ META (CLIENTS): Add a key and List all keys."""
        key = 'key_' + str(uuid())
        ret = self.meta_client.add_key(key=key)
        assert_true(ret)

        keys = self.meta_client.list_keys()
        assert_is_instance(keys, list)
        assert_in(key, keys)

    def test_add_and_list_values(self):
        """ META (CLIENTS): Add a value and List all values."""
        key = 'key_' + str(uuid())
        value = 'value_' + str(uuid())

        ret = self.meta_client.add_key(key=key)
        assert_true(ret)

        ret = self.meta_client.add_value(key=key, value=value)

        values = self.meta_client.list_values(key=key)
        assert_is_instance(values, list)
        assert_in(value, values)
