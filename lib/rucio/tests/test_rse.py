# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

from uuid import uuid4 as uuid
from json import dumps
from nose.tools import raises, assert_equal, assert_true,\
                       assert_items_equal
from paste.fixture import TestApp

from rucio.client.rseclient import RSEClient
from rucio.common.exception import Duplicate, RucioException
from rucio.core.rse import  add_rse, del_rse, list_rses,\
                            rse_exists, set_rse_usage, get_rse_usage,\
                            add_rse_tag, get_rses, list_rse_tags
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.web.rest.rse import app as rse_app
from rucio.web.rest.authentication import app as auth_app


class TestRSECoreApi():

    def setUp(self):
        build_database(echo=False)

    def tearDown(self):
        destroy_database(echo=False)

    def test_create_and_check_for_rse(self):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE """
        rse = 'MOCK'
        invalid_rse = 'BLAHBLAH'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(rse_exists(invalid_rse), False)
        del_rse(rse)

    @raises(Duplicate)
    def test_create_and_create_for_rse(self):
        """ RSE (CORE): Test the double creation of the same RSE """
        rse = 'MOCK'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse(rse)

    def test_list_rses(self):
        """ RSE (CORE): Test the listing of all RSEs """
        rse = 'MOCK'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        rses = list_rses()
        assert_equal(rses, [u'MOCK'])
        del_rse(rse)

    def test_set_rse_usage(self):
        """ RSE (CORE): Test the update of RSE usage """
        rse = 'MOCK'
        source = 'srm'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(set_rse_usage(rse=rse, source=source, total=1000000L, free=80L), True)
        usage = get_rse_usage(rse=rse)
        for u in usage:
            assert_equal(u['total'], 1000000)

    def test_add_rse_tag(self):
        """  RSE (CORE): Test the creation of a rse tag """
        l1 = 'MOCK'
        l2 = 'MOCK2'
        tag = 'TIERS2'
        description = 'cloud'
        add_rse(l1)
        add_rse(l2)
        assert_equal(rse_exists(l1), True)
        add_rse_tag(rse=l1, tag=tag, description=description)
        add_rse_tag(rse=l2, tag=tag, description=description)
        assert_items_equal(get_rses(filters={'rse': 'MOCK'}), [{'rse': u'MOCK', 'tag': u'TIERS2'}])
        assert_items_equal(get_rses(filters={'description': 'cloud'}), [{'rse': u'MOCK', 'tag': u'TIERS2'}, {'rse': u'MOCK2', 'tag': u'TIERS2'}])

    def test_list_rse_tags(self):
        """  RSE (CORE): Test the listing of RSE tags """
        l1 = 'MOCK'
        l2 = 'MOCK2'
        description = 'cloud'
        add_rse(l1)
        add_rse(l2)
        assert_equal(rse_exists(l1), True)
        add_rse_tag(rse=l1, tag='TIERS2', description=description)
        add_rse_tag(rse=l2, tag='TIERS3', description=description)
        rse_tags = list_rse_tags()
        assert_items_equal(['TIERS2', 'TIERS3'], rse_tags)


class TestRSE():

    def setUp(self):
        build_database(echo=False)
        create_root_account()

    def tearDown(self):
        destroy_database(echo=False)

    def test_create_rse_success(self):
        """ RSE (REST): send a POST to create a new RSE """
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
        data = dumps({'rse': 'MOCK'})
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 409)

    def test_list_rses(self):
        """ RSE (REST): send a GET to list all rses """
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
        r3 = TestApp(rse_app.wsgifunc(*mw)).get('/', headers=headers3, expect_errors=True)
        assert_equal(r3.body, '["MOCK"]')
        assert_equal(r3.status, 200)

    def test_tag_rses(self):
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

    def test_list_rse_tags(self):
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
    def setUp(self):
        build_database(echo=False)
        create_root_account()
        self.client = RSEClient()

    def tearDown(self):
        destroy_database(echo=False)

    def test_create_rse(self):
        """ RSE (CLIENTS): create a new rse."""
        location = str(uuid())
        ret = self.client.create_rse(location)
        assert_true(ret)

    @raises(Duplicate)
    def test_create_rse_duplicate(self):
        """ RSE (CLIENTS): create a duplicate rse."""
        location = str(uuid())
        self.client.create_rse(location)
        self.client.create_rse(location)

    def test_list_rses(self):
        """ RSE (CLIENTS): try to list rses."""
        location_list = [str(uuid()) + str(i) for i in xrange(5)]
        try:
            for location in location_list:
                self.client.create_rse(location)

            svr_list = self.client.list_rses()

            for location in location_list:
                if location not in svr_list:
                    assert_true(False)
        except RucioException:
            assert_true(True)
