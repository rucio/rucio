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
import os
import unittest

import pytest

from rucio.common.config import config_get, config_get_bool
from rucio.tests.common import account_name_generator, rse_name_generator, execute, get_long_vo


class TestCurlRucio(unittest.TestCase):
    '''
    class TestCurlRucio
    '''

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo_header = '-H "X-Rucio-VO: %s"' % get_long_vo()
        else:
            self.vo_header = ''

        self.cacert = config_get('test', 'cacert')
        self.usercert = config_get('test', 'usercert')
        self.userkey = config_get('test', 'userkey')
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')
        self.marker = '$> '

    def test_ping(self):
        """PING (CURL): Get Version"""
        cmd = 'curl --cacert %s -s -X GET %s/ping' % (self.cacert, self.host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        ret = json.loads(out)
        assert 'version' in ret
        assert isinstance(ret, dict)

    def test_get_auth_userpass(self):
        """AUTH (CURL): Test auth token retrieval with via username and password"""
        cmd = 'curl -s -i --cacert %s -X GET -H "X-Rucio-Account: root" -H "X-Rucio-Username: ddmlab" -H "X-Rucio-Password: secret" %s %s/auth/userpass' % (self.cacert, self.vo_header, self.auth_host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'X-Rucio-Auth-Token' in out

    def test_get_auth_x509(self):
        """AUTH (CURL): Test auth token retrieval with via x509"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s -cert %s --key %s -X GET %s/auth/x509' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert 'X-Rucio-Auth-Token' in out

    def test_get_auth_GSS(self):
        """AUTH (CURL): Test auth token retrieval with via gss"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --negotiate -u: -X GET %s/auth/gss' % (self.cacert, self.vo_header, self.auth_host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        # assert 'X-Rucio-Auth-Token' in out

    def test_get_auth_x509_proxy(self):
        """AUTH (CURL): Test auth token retrieval with via proxy"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: vgaronne" %s --cert $X509_USER_PROXY --key $X509_USER_PROXY -X GET %s/auth/x509_proxy' % (self.cacert, self.vo_header, self.auth_host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        # assert 'X-Rucio-Auth-Token' in out

    def test_get_auth_validate(self):
        """AUTH (CURL): Test if token is valid"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = 'curl -s -i --cacert %s  -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -X GET %s/auth/validate' % (self.cacert, self.auth_host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert 'datetime.datetime' in out

    @pytest.mark.dirty
    def test_post_account(self):
        """ACCOUNT (CURL): add account"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = '''curl -s -i --cacert %s -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -H "Rucio-Type: user" -H "Content-Type: application/json" -d '{"type": "USER", "email": "rucio@email.com"}' -X POST %s/accounts/%s''' % (self.cacert, self.host, account_name_generator())
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert '201 Created'.lower() in out.lower()

    def test_get_accounts_whoami(self):
        """ACCOUNT (CURL): Test whoami method"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        print(cmd)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = '''curl -s -i -L --cacert %s -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -X GET %s/accounts/whoami''' % (self.cacert, self.host)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert '303 See Other'.lower() in out.lower()

    @pytest.mark.dirty
    def test_post_rse(self):
        """RSE (CURL): add RSE"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = '''curl -s -i --cacert %s -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -X POST %s/rses/%s''' % (self.cacert, self.host, rse_name_generator())
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        assert '201 Created'.lower() in out.lower()
