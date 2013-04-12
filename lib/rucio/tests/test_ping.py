# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import json

from nose.tools import assert_true, assert_equal, assert_is_instance
from paste.fixture import TestApp

from rucio.client.pingclient import PingClient
from rucio.web.rest.ping import app as ping_app


class TestPing():

    def setup(self):
        pass

    def tearDown(self):
        pass

    def test_rucio_ping(self):
        """ RUCIO (REST): test a rucio ping """
        mw = []

        r1 = TestApp(ping_app.wsgifunc(*mw)).get('/', expect_errors=True)
        assert_equal(r1.status, 200)
        ret = json.loads(r1.body)
        assert_true('version' in ret)
        assert_is_instance(ret, dict)


class TestPingClient():

    def setup(self):
        self.client = PingClient()

    def tearDown(self):
        pass

    def test_rucio_ping(self):
        """ RUCIO(CLIENTS): test a rucio ping """
        ret = self.client.ping()
        assert_true('version' in ret)
        assert_is_instance(ret, dict)
