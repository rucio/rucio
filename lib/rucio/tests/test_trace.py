# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import datetime
import json
import time
import uuid

from nose.tools import assert_equal
from paste.fixture import TestApp

from rucio.web.rest.trace import app as trace_app


class TestTrace():

    def test_submit_trace(self):
        """ TRACE (REST): submit a trace via POST """

        mw = []

        payload = json.dumps({'uuid': str(uuid.uuid4()),  # not JSON serialisable
                              'string': 'deadbeef',
                              'hex': 0xDEADBEEF,
                              'int': 3,
                              'float': 3.14,
                              'long': 314314314314314314L,
                              'timestamp': time.time(),
                              'datetime_str': str(datetime.datetime.utcnow()),  # not JSON serialisable
                              'boolean': True})

        r = TestApp(trace_app.wsgifunc(*mw)).post('/', params=payload, headers={'Content-Type': 'application/octet-stream'})
        assert_equal(r.status, 201)
