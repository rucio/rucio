# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import json

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
        assert result.status == 200
        ret = json.loads(result.body.decode())
        assert 'version' in ret
        assert isinstance(ret, dict)


class TestPingClient(object):
    '''
        class TestPingClient
    '''
    def test_rucio_ping(self):
        """ RUCIO(CLIENTS): test a rucio ping """
        client = PingClient()
        ret = client.ping()
        assert 'version' in ret
        assert isinstance(ret, dict)
