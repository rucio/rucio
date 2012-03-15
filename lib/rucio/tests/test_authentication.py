# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from nose.tools import *
from paste.fixture import TestApp
from sqlalchemy import create_engine

from rucio.common.config import config_get
from rucio.web.rest.authentication import app
import rucio.db.models1 as models


class TestGET():

    def setUp(self):
        engine = create_engine(config_get('database', 'default'))
        models.register_models(engine)

    def tearDown(self):
        engine = create_engine(config_get('database', 'default'))
        models.unregister_models(engine)

    def test_auth_header_userpass_fail(self):
        """Authenticate a Rucio account temporarily via username and password (wrong credentials)."""

        mw = []
        headers = {'Rucio-Account': 'wrong', 'Rucio-Username': 'wrong', 'Rucio-Password': 'wrong'}
        r = TestApp(app.wsgifunc(*mw)).get('/auth/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 401)

    def test_auth_header_userpass_success(self):
        """Authenticate a Rucio account temporarily via username and password (correct credentials)."""

        mw = []
        headers = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r = TestApp(app.wsgifunc(*mw)).get('/auth/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        assert_equal(len(r.header('Rucio-Auth-Token')), 32)


class TestPUT():

    pass


class TestPOST():

    pass


class TestDELETE():

    pass
