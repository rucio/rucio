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

import datetime
import time
import uuid
import logging
import pytest
import json
from rucio.common.schema.generic import IPv4orIPv6
from rucio.core.trace import SCHEMAS, validate_schema
from rucio.common.exception import InvalidObject


LOGGER = logging.getLogger(__name__)


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


def test_submit_trace_wrong_content_type(rest_client):
    """
    TRACE (REST): submit data with wrong Content-Type to check backwards-compatibility.
    This emulates the Content-Type default of a curl POST.
    """
    response = rest_client.post('/traces/', data='{"a": "b"}', content_type=[('Content-Type', 'application/x-www-form-urlencoded')])
    assert response.status_code == 201


def test_trace_ip():
    """
    Allow either IPv4 or IPv6 addresses as traceIp fields
    """
    TEST_SCHEMA = {
        "type": "object",
        "properties": {
            "eventType": {"enum": ["test"]},
            "traceIp": IPv4orIPv6
        }
    }

    SCHEMAS['test'] = TEST_SCHEMA

    valid_ips = [
        "::ffff:134.158.121.5",
        "126.36.54.98"
    ]
    invalid_ips = [
        "::ffff:134.158.121.5:80",
        "300.25.45.98",
        "128.69.32.45:80"
    ]
    valid_obj = [json.dumps({"eventType": "test", "traceIp": ip}) for ip in valid_ips]
    invalid_obj = [json.dumps({"eventType": "test", "traceIp": ip}) for ip in invalid_ips]

    for obj in valid_obj:
        validate_schema(obj)

    for obj in invalid_obj:
        with pytest.raises(InvalidObject):
            validate_schema(obj)


def test_non_existant_event_type_validation_rejection(caplog):
    """
    Test if an incoming trace with a non-supported schema logs a warning
    instead of printing entire stack-trace
    """
    event_type = "put_new_type"
    obj = json.dumps({"eventType": f"{event_type}"})
    validate_schema(obj)
    assert f"schema for eventType {event_type} is not currently supported" in caplog.text
