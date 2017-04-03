'''
  Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
 - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011-2017
'''

from nose.tools import assert_equal, assert_is_not_none, assert_greater
from paste.fixture import TestApp

from rucio.api.authentication import get_auth_token_user_pass
from rucio.web.rest.authentication import APP


class TestAuthCoreApi(object):
    '''
    TestAuthCoreApi
    '''
    def test_get_auth_token_user_pass(self):
        """AUTHENTICATION (CORE): Username and password (correct credentials)."""
        result = get_auth_token_user_pass(account='root', username='ddmlab', password='secret', appid='test', ip='127.0.0.1')
        assert_is_not_none(result)


class TestAuthRestApi(object):
    '''
    TestAuthRestApi
    '''
    def test_userpass_fail(self):
        """AUTHENTICATION (REST): Username and password (wrong credentials)."""
        options = []
        headers = {'X-Rucio-Account': 'wrong', 'X-Rucio-Username': 'wrong', 'X-Rucio-Password': 'wrong'}
        result = TestApp(APP.wsgifunc(*options)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(result.status, 401)

    def test_userpass_success(self):
        """AUTHENTICATION (REST): Username and password (correct credentials)."""
        options = []
        headers = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        result = TestApp(APP.wsgifunc(*options)).get('/userpass', headers=headers, expect_errors=True)
        assert_equal(result.status, 200)
        assert_greater(len(result.header('X-Rucio-Auth-Token')), 32)
