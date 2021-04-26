# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2019
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

from __future__ import print_function

import unittest
from datetime import datetime, timedelta

try:
    from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
    from http.server import SimpleHTTPRequestHandler
try:
    from SocketServer import TCPServer as HTTPServer
except ImportError:
    from http.server import HTTPServer
from os import remove
from threading import Thread

import pytest

from rucio.client.baseclient import BaseClient
from rucio.client.client import Client
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import CannotAuthenticate, ClientProtocolNotSupported, RucioException
from rucio.common.utils import get_tmp_dir
from rucio.tests.common import get_long_vo


class MockServer:
    """
    Start A simple http server in a separate thread to serve as MOCK for testing the client
    """

    class Handler(SimpleHTTPRequestHandler):
        def send_code_and_message(self, code, headers, message):
            """
            Helper which wraps the quite-low-level BaseHTTPRequestHandler primitives and is used to send reponses.
            """
            self.send_response(code)
            self.send_header("Content-type", "text/plain")
            for name, content in headers.items():
                self.send_header(name, content)
            self.end_headers()
            self.wfile.write(message.encode())

    def __init__(self, request_handler_cls):
        self.server = HTTPServer(('localhost', 0), request_handler_cls)
        self.thread = Thread(target=self.server.serve_forever)
        self.thread.daemon = True

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    @property
    def base_url(self):
        name, port = self.server.server_address
        return 'http://{}:{}'.format(name, port)


@pytest.mark.noparallel(reason='fails when run in parallel')
class TestBaseClient(unittest.TestCase):
    """ To test Clients"""

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_long_vo()}
            try:
                remove(get_tmp_dir() + '/.rucio_root@%s/auth_token_root' % self.vo['vo'])
            except OSError as error:
                if error.args[0] != 2:
                    raise error

        else:
            self.vo = {}

        self.cacert = config_get('test', 'cacert')
        self.usercert = config_get('test', 'usercert')
        self.userkey = config_get('test', 'userkey')
        try:
            remove(get_tmp_dir() + '/.rucio_root/auth_token_root')
        except OSError as error:
            if error.args[0] != 2:
                raise error

    def testUserpass(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, **self.vo)

    def testUserpassWrongCreds(self):
        """ CLIENTS (BASECLIENT): try to authenticate with wrong username."""
        creds = {'username': 'wrong', 'password': 'secret'}
        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, **self.vo)

    def testUserpassNoCACert(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass without ca cert."""
        creds = {'username': 'wrong', 'password': 'secret'}
        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', auth_type='userpass', creds=creds, **self.vo)

    def testx509(self):
        """ CLIENTS (BASECLIENT): authenticate with x509."""
        creds = {'client_cert': self.usercert,
                 'client_key': self.userkey}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, **self.vo)

    def testx509NonExistingCert(self):
        """ CLIENTS (BASECLIENT): authenticate with x509 with missing certificate."""
        creds = {'client_cert': '/opt/rucio/etc/web/notthere.crt'}
        with pytest.raises(CannotAuthenticate):
            BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, **self.vo)

    def testClientProtocolNotSupported(self):
        """ CLIENTS (BASECLIENT): try to pass an host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        with pytest.raises(ClientProtocolNotSupported):
            BaseClient(rucio_host='localhost', auth_host='junk://localhost', account='root', auth_type='userpass', creds=creds, **self.vo)

    def testRetryOn502AlwaysFail(self):
        """ CLIENTS (BASECLIENT): Ensure client retries on 502 error codes, but fails on repeated errors"""

        class AlwaysFailWith502(MockServer.Handler):
            def do_GET(self):
                self.send_code_and_message(502, {}, '')

        with MockServer(AlwaysFailWith502) as server:
            with pytest.raises(CannotAuthenticate):
                creds = {'username': 'ddmlab', 'password': 'secret'}
                BaseClient(rucio_host=server.base_url, auth_host=server.base_url, account='root', auth_type='userpass', creds=creds, **self.vo)
            with pytest.raises(RucioException):
                creds = {'client_cert': self.usercert,
                         'client_key': self.userkey}
                BaseClient(rucio_host=server.base_url, auth_host=server.base_url, account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, **self.vo)

    def testRetryOn502SucceedsEventually(self):
        """ CLIENTS (BASECLIENT): Ensure client retries on 502 error codes"""
        invocations = []

        class FailTwiceWith502(MockServer.Handler):
            def do_GET(self, invocations=invocations):
                invocations.append(self.path)
                if len(invocations) <= 2:
                    self.send_code_and_message(502, {}, '')
                else:
                    self.send_code_and_message(200, {'x-rucio-auth-token': 'sometoken'}, '')

        start_time = datetime.utcnow()
        with MockServer(FailTwiceWith502) as server:
            creds = {'username': 'ddmlab', 'password': 'secret'}
            del invocations[:]
            client = BaseClient(rucio_host=server.base_url, auth_host=server.base_url, account='root', auth_type='userpass', creds=creds, **self.vo)
            del invocations[:]
            client._send_request(server.base_url)  # noqa
        # The client did back-off multiple times before succeeding: 2 * 0.25s (authentication) + 2 * 0.25s (request) = 1s
        assert datetime.now() - start_time > timedelta(seconds=0.9)


class TestRucioClients(unittest.TestCase):
    """ To test Clients"""

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_long_vo()}
        else:
            self.vo = {}

        self.cacert = config_get('test', 'cacert')
        self.marker = '$> '

    def test_ping(self):
        """ PING (CLIENT): Ping Rucio """
        creds = {'username': 'ddmlab', 'password': 'secret'}

        client = Client(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, **self.vo)

        print(client.ping())
