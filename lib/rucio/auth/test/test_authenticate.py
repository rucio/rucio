"""
@copyright: European Organization for Nuclear Research (CERN)
@contact: U{ph-adp-ddm-lab@cern.ch<mailto:ph-adp-ddm-lab@cern.ch>}
@license: Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at:
U{http://www.apache.org/licenses/LICENSE-2.0}
@author:
- Mario Lassnig, <mario.lassnig@cern.ch>, CERN PH-ADP-CO, 2012
"""

from paste.fixture import TestApp

from rucio.auth.authenticate import app


class TestGET():
    """Authentication unittests for GET requests"""

    def test_auth_exists(self):
        """Authentication endpoint must exist"""

        mw = []
        headers = {}
        r = TestApp(app.wsgifunc(*mw)).get('/authenticate', headers=headers, expect_errors=True)
        assert r.status, 200

    def test_validate_exists(self):
        """Validation endpoint must exist"""

        mw = []
        headers = {}
        r = TestApp(app.wsgifunc(*mw)).get('/validate', headers=headers, expect_errors=True)
        assert r.status, 200

    def test_auth_header_userpass_success(self):
        """Authenticate account via header username/password"""

        mw = []
        headers = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'testuser', 'Rucio-Password': 'testpassword'}
        r = TestApp(app.wsgifunc(*mw)).get('/authenticate', headers=headers, expect_errors=True)
        assert r.status, 200

    def test_auth_header_userpass_wrong_pass(self):
        """Authenticate account via header username/password, wrong password"""

        mw = []
        headers = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'testuser', 'Rucio-Password': 'wrongpass'}
        r = TestApp(app.wsgifunc(*mw)).get('/authenticate', headers=headers, expect_errors=True)
        assert r.status, 401

    def test_auth_header_userpass_no_account(self):
        """Authenticate account via header username/password, missing account"""

        mw = []
        headers = {'Rucio-Username': 'testuser', 'Rucio-Password': 'testpassword'}
        r = TestApp(app.wsgifunc(*mw)).get('/authenticate', headers=headers, expect_errors=True)
        assert r.status, 400


class TestPUT():

    pass


class TestPOST():

    pass


class TestDELETE():

    pass
