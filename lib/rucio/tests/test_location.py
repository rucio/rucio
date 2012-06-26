# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import uuid

import json

from nose.tools import *
from paste.fixture import TestApp
from sqlalchemy import create_engine

from rucio.common.config import config_get
from rucio.common import exception
from rucio.core.location import add_location, location_exists, del_location, list_locations
from rucio.db import models1 as models
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.web.rest.location import app as location_app
from rucio.web.rest.authentication import app as auth_app


class TestLocation_core_api():

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

    @raises(exception.Duplicate, ValueError)
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
        """ LOCATION (REST): send a POST to create a new location """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(location_app.wsgifunc(*mw)).post('/MOCK', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

    def test_list_locations(self):
        """ LOCATION (REST): send a GET to list all locations """
        mw = []

        headers1 = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(location_app.wsgifunc(*mw)).post('/MOCK', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'Rucio-Type': 'user', 'Rucio-Account': 'root', 'Rucio-Auth-Token': str(token)}
        r3 = TestApp(location_app.wsgifunc(*mw)).get('/', headers=headers3, expect_errors=True)
        assert_equal(r3.body, '["MOCK"]')
        assert_equal(r3.status, 200)
