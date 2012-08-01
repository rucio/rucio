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

from nose.tools import raises, assert_equal, assert_true
from paste.fixture import TestApp

from rucio.client.locationclient import LocationClient
from rucio.common.exception import Duplicate
from rucio.core.location import add_location, location_exists, del_location, list_locations
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.web.rest.location import app as location_app
from rucio.web.rest.authentication import app as auth_app


class TestLocationCoreApi():

    def setUp(self):
        build_database()

    def tearDown(self):
        destroy_database()

    def test_create_and_check_for_location(self):
        """ LOCATION (CORE): Test the creation, query, and deletion of a location """
        location = 'MOCK'
        invalid_location = 'BLAHBLAH'
        add_location(location)
        assert_equal(location_exists(location), True)
        assert_equal(location_exists(invalid_location), False)
        del_location(location)

    @raises(Duplicate)
    def test_create_and_create_for_location(self):
        """ LOCATION (CORE): Test the double creation of the same location """
        location = 'MOCK'
        add_location(location)
        assert_equal(location_exists(location), True)
        add_location(location)

    def test_list_locations(self):
        """ LOCATION (CORE): Test the listing of all locations """
        location = 'MOCK'
        add_location(location)
        assert_equal(location_exists(location), True)
        locations = list_locations()
        assert_equal(locations, [u'MOCK'])
        del_location(location)


class TestLocation():

    def setUp(self):
        build_database()
        create_root_account()

    def tearDown(self):
        destroy_database()

    def test_create_location_success(self):
        """ LOCATION (REST): send a PUT to create a new location """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(location_app.wsgifunc(*mw)).put('/MOCK', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

    def test_list_locations(self):
        """ LOCATION (REST): send a GET to list all locations """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(location_app.wsgifunc(*mw)).put('/MOCK', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(location_app.wsgifunc(*mw)).get('/', headers=headers3, expect_errors=True)
        assert_equal(r3.body, '["MOCK"]')
        assert_equal(r3.status, 200)


class xTestLocationClient():
    def setUp(self):
        creds = {'username': 'ddmlab', 'password': 'secret'}
        self.client = LocationClient(rucio_host='localhost', auth_host='localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

    def tearDown(self):
        pass

    def test_create_location(self):
        """ LOCATION (CLIENTS): create a new location."""
        location = str(uuid())
        ret = self.client.create_location(location)
        assert_true(ret)

    @raises(Duplicate)
    def test_create_location_duplicate(self):
        """ LOCATION (CLIENTS): create a duplicate location."""
        location = str(uuid())
        self.client.create_location(location)
        self.client.create_location(location)

    def test_list_locations(self):
        """ LOCATION (CLIENTS): try to list locations."""
        location_list = [str(uuid()) + str(i) for i in xrange(5)]

        for location in location_list:
            self.client.create_location(location)

        svr_list = self.client.list_locations()

        for location in location_list:
            if location not in svr_list:
                assert_true(False)
