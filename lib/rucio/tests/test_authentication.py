# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from nose.tools import assert_equal
from paste.fixture import TestApp

from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.web.rest.authentication import app


class TestGET():

    def setUp(self):
        build_database()
        create_root_account()

    def tearDown(self):
        destroy_database()

    def test_userpass_fail(self):
        """AUTHENTICATION (REST): Username and password (wrong credentials)."""

        mw = []
        headers = {'Rucio-Account': 'wrong', 'Rucio-Username': 'wrong', 'Rucio-Password': 'wrong'}
        r = TestApp(app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 401)

    def test_userpass_success(self):
        """AUTHENTICATION (REST): Username and password (correct credentials)."""

        mw = []
        headers = {'Rucio-Account': 'root', 'Rucio-Username': 'ddmlab', 'Rucio-Password': 'secret'}
        r = TestApp(app.wsgifunc(*mw)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(r.status, 200)
        assert_equal(len(r.header('Rucio-Auth-Token')), 32)

    def test_x509(self):
        """AUTHENTICATION (REST): Placeholder for now, as unittest/nose/paste do not support SSL handshake. Check tools/test_auth.sh"""
        pass

    def test_gss(self):
        """AUTHENTICATION (REST): Placeholder for now, as unittest/nose/paste do not support GSSAPI handshake. Check tools/test_auth.sh"""
        pass


class TestPUT():

    pass


class TestPOST():

    pass


class TestDELETE():

    pass
