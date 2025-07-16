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

import pytest

from rucio.common.config import config_get, config_get_bool
from rucio.tests.common import account_name_generator, execute, get_long_vo, rse_name_generator, skip_outside_gh_actions


class TestCurlRucio:
    '''
    class TestCurlRucio
    '''

    vo_header = ''
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo_header = '-H "X-Rucio-VO: %s"' % get_long_vo()
    cacert = config_get('test', 'cacert')
    usercert = config_get('test', 'usercert')
    userkey = config_get('test', 'userkey')
    host = config_get('client', 'rucio_host')
    auth_host = config_get('client', 'auth_host')
    marker = '$> '

    def test_ping(self):
        """PING (CURL): Get Version"""
        cmd = 'curl --cacert %s -s -X GET %s/ping' % (self.cacert, self.host)
        exitcode, out, err = execute(cmd)
        ret = json.loads(out)
        assert exitcode == 0, f"Ping failed: {self.marker} {cmd}"
        assert 'version' in ret, f"Version not found in response : {out} {ret}"
        assert isinstance(ret, dict)

    def test_get_auth_userpass(self):
        """AUTH (CURL): Test auth token retrieval with via username and password"""
        cmd = 'curl -s -i --cacert %s -X GET -H "X-Rucio-Account: root" -H "X-Rucio-Username: ddmlab" -H "X-Rucio-Password: secret" %s %s/auth/userpass' % (self.cacert, self.vo_header, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Auth token retrieval failed: {self.marker} {cmd}"
        assert 'X-Rucio-Auth-Token' in out, f"Auth token not found in response: {out}"

    @skip_outside_gh_actions
    def test_get_auth_x509(self):
        """AUTH (CURL): Test auth token retrieval with via x509"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s -cert %s --key %s -X GET %s/auth/x509' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Auth token retrieval failed: {self.marker} {cmd}"
        assert 'X-Rucio-Auth-Token' in out, f"Auth token not found in response: {out}"

    def test_get_auth_gss(self):
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

    @skip_outside_gh_actions
    def test_get_auth_validate(self):
        """AUTH (CURL): Test if token is valid"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = 'curl -s -i --cacert %s  -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -X GET %s/auth/validate' % (self.cacert, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Token validation failed: {self.marker} {cmd}"
        assert 'datetime.datetime' in out, f"Token validation failed: {out}"

    @skip_outside_gh_actions
    @pytest.mark.dirty
    def test_post_account(self):
        """ACCOUNT (CURL): add account"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()

        cmd = ("curl -s -i --cacert %s "
               '-H "X-Rucio-Auth-Token: $RUCIO_TOKEN" '
               '-H "Rucio-Type: user" '
               '-H "Content-Type: application/json" '
               "-d '{\"type\": \"USER\", \"email\": \"rucio@email.com\"}' "
               "-X POST %s/accounts/%s"
               ) % (self.cacert, self.host, account_name_generator())
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Account creation failed: {self.marker} {cmd}"
        assert '201 Created'.lower() in out.lower(), f"Account creation failed: {out}"

    @skip_outside_gh_actions
    def test_get_accounts_whoami(self):
        """ACCOUNT (CURL): Test whoami method"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Auth token retrieval failed: {cmd}"
        assert 'X-Rucio-Auth-Token' in out, f"Auth token not found in response: {out}"
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = '''curl -s -i -L --cacert %s -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -X GET %s/accounts/whoami''' % (self.cacert, self.host)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Whoami failed: {self.marker} {cmd}"
        assert '303 See Other'.lower() in out.lower(), f"Whoami failed: {out}"

    @skip_outside_gh_actions
    @pytest.mark.dirty
    def test_post_rse(self):
        """RSE (CURL): add RSE"""
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Account: root" %s --cert %s --key %s -X GET %s/auth/x509 | tr -d \'\r\' | grep X-Rucio-Auth-Token:' % (self.cacert, self.vo_header, self.usercert, self.userkey, self.auth_host)
        exitcode, out, err = execute(cmd)
        assert 'X-Rucio-Auth-Token' in out
        os.environ['RUCIO_TOKEN'] = out[len('X-Rucio-Auth-Token: '):].rstrip()
        cmd = '''curl -s -i --cacert %s -H "X-Rucio-Auth-Token: $RUCIO_TOKEN" -X POST %s/rses/%s''' % (self.cacert, self.host, rse_name_generator())
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"RSE creation failed: {self.marker} {cmd}"
        assert '201 Created'.lower() in out.lower(), f"RSE creation failed: {out}"
