# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from paste.fixture import TestApp
from nose.tools import *

from rucio.web.rest.authentication import app


class TestGET():

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
