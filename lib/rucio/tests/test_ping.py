''' Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
'''

import json

from nose.tools import assert_true, assert_equal, assert_is_instance
from paste.fixture import TestApp

from rucio.client.pingclient import PingClient
from rucio.web.rest.ping import APP as ping_app


class TestPing(object):
    '''
        class TestPing
    '''
    def test_rucio_ping(self):
        """ RUCIO (REST): test a rucio ping """
        options = []
        result = TestApp(ping_app.wsgifunc(*options)).get('/', expect_errors=True)
        assert_equal(result.status, 200)
        ret = json.loads(result.body.decode())
        assert_true('version' in ret)
        assert_is_instance(ret, dict)


class TestPingClient(object):
    '''
        class TestPingClient
    '''
    def test_rucio_ping(self):
        """ RUCIO(CLIENTS): test a rucio ping """
        client = PingClient()
        ret = client.ping()
        assert_true('version' in ret)
        assert_is_instance(ret, dict)
