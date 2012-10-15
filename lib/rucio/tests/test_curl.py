# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# How to generate test outputs:
#   nosetests --verbose --with-outputsave --save-directory=doc/source/example_outputs/ lib/rucio/tests/test_curl.py

import json
import os
import nose.tools

from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.tests.common import execute


class TestCurlRucio():

    @classmethod
    def setUpClass(cls):
        build_database(echo=False)
        create_root_account()

    @classmethod
    def tearDownClass(cls):
        destroy_database(echo=False)

    def setUp(self):
        self.marker = '$> '

    def test_ping(self):
        """PING (CURL): Get Version"""
        cmd = 'curl -s  -X GET http://localhost/ping'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        ret = json.loads(out)
        nose.tools.assert_true('version' in ret)
        nose.tools.assert_is_instance(ret, dict)

    def test_get_auth_userpass(self):
        """AUTH (CURL): Test auth token retrieval with via username and password"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt  -X GET -H "Rucio-Account: root" -H "Rucio-Username: ddmlab" -H "Rucio-Password: secret" https://localhost/auth/userpass'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_in('Rucio-Auth-Token', out)

    def test_get_auth_x509(self):
        """AUTH  (CURL): Test auth token retrieval with via x509"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        nose.tools.assert_in('Rucio-Auth-Token', out)

    def test_get_auth_GSS(self):
        """AUTH (CURL): Test auth token retrieval with via gss"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Rucio-Auth-Token', out)
        os.environ['RUCIO_TOKEN'] = out[len('Rucio-Auth-Token: '):-1]
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" --negotiate -u: -X GET https://localhost/auth/gss'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        # nose.tools.assert_in('Rucio-Auth-Token', out)

    def test_get_auth_x509_proxy(self):
        """AUTH (CURL): Test auth token retrieval with via proxy"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Rucio-Auth-Token', out)
        os.environ['RUCIO_TOKEN'] = out[len('Rucio-Auth-Token: '):-1]
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: vgaronne" --cert $X509_USER_PROXY --key $X509_USER_PROXY -X GET https://localhost/auth/x509_proxy'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out,
        # nose.tools.assert_in('Rucio-Auth-Token', out)

    def test_get_auth_validate(self):
        """AUTH (CURL): Test if token is valid"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Rucio-Auth-Token', out)
        os.environ['RUCIO_TOKEN'] = out[len('Rucio-Auth-Token: '):-1]
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt  -H "Rucio-Auth-Token: $RUCIO_TOKEN" -X GET https://localhost/auth/validate'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        nose.tools.assert_in('datetime.datetime', out)

    def test_post_account(self):
        """ACCOUNT (CURL): add account"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Rucio-Auth-Token', out)
        os.environ['RUCIO_TOKEN'] = out[len('Rucio-Auth-Token: '):-1]
        cmd = '''curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RUCIO_TOKEN" -H "Rucio-Type: user" -d '{"accountType": "user"}' -X POST https://localhost/accounts/jdoe'''
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        nose.tools.assert_in('201 Created', out)

    def test_get_accounts_whoami(self):
        """ACCOUNT (CURL): Test whoami method"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Rucio-Auth-Token', out)
        os.environ['RUCIO_TOKEN'] = out[len('Rucio-Auth-Token: '):-1]
        cmd = '''curl -s -i -L --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RUCIO_TOKEN" -X GET https://localhost/accounts/whoami'''
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        nose.tools.assert_in('303 See Other', out)

    def test_post_rse(self):
        """RSE (CURL): add RSE"""
        cmd = 'curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token'
        exitcode, out, err = execute(cmd)
        nose.tools.assert_in('Rucio-Auth-Token', out)
        os.environ['RUCIO_TOKEN'] = out[len('Rucio-Auth-Token: '):-1]
        cmd = '''curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RUCIO_TOKEN" -H "Rucio-Type: user" -X POST https://localhost/rses/MOCK'''
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        nose.tools.assert_in('201 Created', out)
