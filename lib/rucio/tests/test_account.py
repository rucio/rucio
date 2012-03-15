# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

import json

from paste.fixture import TestApp
from nose.tools import *

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from rucio.db import models1 as models
from rucio.web.rest.account import app


class TestAccount():

    def setUp(self):
        engine = create_engine('sqlite:////tmp/rucio.db', echo=True)
        models.register_models(engine)

    def tearDown(self):
        engine = create_engine('sqlite:////tmp/rucio.db', echo=True)
        models.unregister_models(engine)

    def test_create_user_success(self):
        """ send a POST to create a new user """
        mw = []
        headers = {'Rucio-Type': 'user'}
        r = TestApp(app.wsgifunc(*mw)).post('/account/testuser', headers=headers, expect_errors=True)
        assert_equal(r.status, 201)

    def test_create_user_failure(self):
        """ send a POST with an existing user to test the error """
        mw = []
        headers = {'Rucio-Type': 'user'}
        r1 = TestApp(app.wsgifunc(*mw)).post('/account/testuser', headers=headers, expect_errors=True)
        r2 = TestApp(app.wsgifunc(*mw)).post('/account/testuser', headers=headers, expect_errors=True)
        assert_equal(r2.status, 500)

    def test_get_user_success(self):
        """ send a GET to retrieve the infos of the new user """
        mw = []
        headers1 = {'Rucio-Type': 'user'}
        headers2 = {}
        r1 = TestApp(app.wsgifunc(*mw)).post('/account/testuser', headers=headers1, expect_errors=True)
        r2 = TestApp(app.wsgifunc(*mw)).get('/account/testuser', headers=headers2, expect_errors=True)
        body = json.loads(r2.body)
        assert_equal(body['account'], 'testuser')
        assert_equal(r2.status, 200)

    def test_get_user_failure(self):
        """ send a GET with a wrong user test the error """
        mw = []
        headers2 = {}
        r = TestApp(app.wsgifunc(*mw)).get('/account/wronguser', headers=headers2, expect_errors=True)
        assert_equal(r.status, 500)

    def test_del_user_success(self):
        """ send a DELETE to disable the new user """
        mw = []
        headers1 = {'Rucio-Type': 'user'}
        headers2 = {}
        r1 = TestApp(app.wsgifunc(*mw)).post('/account/testuser', headers=headers1, expect_errors=True)
        r2 = TestApp(app.wsgifunc(*mw)).delete('/account/testuser', headers=headers2, expect_errors=True)
        r3 = TestApp(app.wsgifunc(*mw)).get('/account/testuser', headers=headers2, expect_errors=True)
        body = json.loads(r3.body)
        assert_true(body['deleted'])
        assert_equal(r2.status, 200)

    def test_del_user_failure(self):
        """ send a DELETE with a wrong user to test the error """
        mw = []
        headers = {}
        r = TestApp(app.wsgifunc(*mw)).delete('/account/wronguser', headers=headers, expect_errors=True)
        assert_equal(r.status, 500)
