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

from rucio.common.config import config_get
from rucio.db import models1 as models
from rucio.web.rest.rse import app as rse_app
from rucio.web.rest.authentication import app as auth_app


class TestRSE():

    def setUp(self):
        engine = create_engine(config_get('database', 'default'))
        models.register_models(engine)

    def tearDown(self):
        engine = create_engine(config_get('database', 'default'))
        models.unregister_models(engine)

    def test_create_rse_success(self):
        """ send a POST to create a new rse """
        mw = []

        headers1 = {'Rucio-Account': 'ddmlab', 'Rucio-Username': 'mlassnig', 'Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/auth/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('Rucio-Auth-Token'))

        headers2 = {'Rucio-Account': 'ddmlab', 'Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/rse/MOCK', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)
