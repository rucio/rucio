# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import json

from rucio.client.pingclient import PingClient


def test_rucio_ping_rest(rest_client):
    """ RUCIO (REST): test a rucio ping """
    response = rest_client.get('/ping')
    assert response.status_code == 200
    ret = json.loads(response.get_data(as_text=True))
    assert 'version' in ret
    assert isinstance(ret, dict)


def test_rucio_ping():
    """ RUCIO (CLIENTS): test a rucio ping """
    client = PingClient()
    ret = client.ping()
    assert 'version' in ret
    assert isinstance(ret, dict)
