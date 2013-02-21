# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from json import dumps, loads
from nose.tools import raises, assert_equal, assert_true, assert_in, assert_raises
from paste.fixture import TestApp

from rucio.client.rseclient import RSEClient
from rucio.common.exception import Duplicate, InvalidObject
from rucio.common.utils import generate_uuid as uuid
from rucio.core.rse import add_rse, del_rse, list_rses,\
    rse_exists, set_rse_usage, get_rse_usage, add_rse_attribute
from rucio.web.rest.rse import app as rse_app
from rucio.web.rest.authentication import app as auth_app


class TestRSECoreApi():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_check_for_rse(self):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE """
        rse = 'MOCK_' + str(uuid())
        invalid_rse = 'BLAHBLAH'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(rse_exists(invalid_rse), False)
        del_rse(rse)

    @raises(Duplicate)
    def test_create_and_create_for_rse(self):
        """ RSE (CORE): Test the double creation of the same RSE """
        rse = 'MOCK_' + str(uuid())
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse(rse)

    def test_list_rses(self):
        """ RSE (CORE): Test the listing of all RSEs """
        rse = u'MOCK_' + str(uuid())
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse_attribute(rse=rse, key='tier', value='1')
        rses = list_rses(filters={'tier': '1'})
        assert_in(rse, rses)
        del_rse(rse)

    def test_list_rses2(self):
        """ RSE (CORE): Test the listing of all RSEs with multiple filters"""
        rse = u'MOCK_' + str(uuid())
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse_attribute(rse=rse, key='tier', value='1')
        add_rse_attribute(rse=rse, key='country', value='us')
        rses = list_rses(filters={'tier': '1', 'country': 'us'})
        assert_in(rse, rses)
        del_rse(rse)

    def test_set_rse_usage(self):
        """ RSE (CORE): Test the update of RSE usage """
        rse = 'MOCK_' + str(uuid())
        source = 'srm'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(set_rse_usage(rse=rse, source=source, total=1000000L, free=80L), True)
        usage = get_rse_usage(rse=rse)
        for u in usage:
            assert_equal(u['total'], 1000000)


class TestRSE():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_rse_success(self):
        """ RSE (REST): send a POST to create a new RSE """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))
        rse = 'MOCK_' + str(uuid())

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 409)

    def test_list_rses(self):
        """ RSE (REST): send a GET to list all rses """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))
        rse = 'MOCK_' + str(uuid())

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(rse_app.wsgifunc(*mw)).get('/', headers=headers3, expect_errors=True)
        assert_in(rse, loads(r3.body))
        assert_equal(r3.status, 200)

    def xtest_tag_rses(self):
        """ RSE (REST): send a POST to tag a RSE """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        data = dumps({'rse': 'MOCK'})
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        data = dumps({'tag': 'MOCK_TAG'})
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/MOCK/tags', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

    def xtest_list_rse_tags(self):
        """ RSE (REST): Test the listing of RSE tags """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        data = dumps({'rse': 'MOCK'})
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        data = dumps({'tag': 'MOCK_TAG'})
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/MOCK/tags', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

        headers4 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r4 = TestApp(rse_app.wsgifunc(*mw)).get('/MOCK/tags', headers=headers4, expect_errors=True)
        assert_equal(r4.status, 200)


class TestRSEClient():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.client = RSEClient()

    def test_add_rse(self):
        """ RSE (CLIENTS): add a new rse."""
        rse = 'MOCK_' + str(uuid())
        ret = self.client.add_rse(rse)
        assert_true(ret)

        with assert_raises(Duplicate):
            self.client.add_rse(rse)

        bad_rse = 'MOCK_$*&##@!'
        with assert_raises(InvalidObject):
            ret = self.client.add_rse(bad_rse)

    def test_list_rses(self):
        """ RSE (CLIENTS): try to list rses."""
        rse_list = ['MOCK_' + str(uuid()) + str(i) for i in xrange(5)]
        for rse in rse_list:
            self.client.add_rse(rse)

        svr_list = self.client.list_rses()

        for rse in rse_list:
            assert_in(rse, svr_list)
