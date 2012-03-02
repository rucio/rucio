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

from nose.tools import assert_equal
from paste.fixture import TestApp

from rucio.auth import authenticate


class TestAuthenticate():

    def test_authenticate(self):
        middleware = []
        testApp = TestApp(authenticate.wsgifunc(*middleware))
        assert_equal(r.status, 200)
        r.mustcontain('auth token')
