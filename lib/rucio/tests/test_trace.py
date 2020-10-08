# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import datetime
import time
import uuid


def test_submit_trace(rest_client):
    """ TRACE (REST): submit a trace via POST """
    payload = {'uuid': str(uuid.uuid4()),  # str, because not JSON serializable
               'string': 'deadbeef',
               'hex': 0xDEADBEEF,
               'int': 3,
               'float': 3.14,
               'long': 314314314314314314,
               'timestamp': time.time(),
               'datetime_str': str(datetime.datetime.utcnow()),  # str, because not JSON serializable
               'boolean': True}

    response = rest_client.post('/traces/', json=payload, content_type=[('Content-Type', 'application/octet-stream')])
    assert response.status_code == 201
