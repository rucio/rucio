# Copyright 2012-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2019
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from __future__ import print_function

from os import remove

from nose.tools import raises

from rucio.client.baseclient import BaseClient
from rucio.client.client import Client
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import get_tmp_dir
from rucio.common.exception import CannotAuthenticate, ClientProtocolNotSupported


class TestBaseClient(object):
    """ To test Clients"""

    def setup(self):
        '''
        __init__
        '''
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
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

    @raises(CannotAuthenticate)
    def testUserpassWrongCreds(self):
        """ CLIENTS (BASECLIENT): try to authenticate with wrong username."""
        creds = {'username': 'wrong', 'password': 'secret'}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, **self.vo)

    @raises(CannotAuthenticate)
    def testUserpassNoCACert(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass without ca cert."""
        creds = {'username': 'wrong', 'password': 'secret'}
        BaseClient(account='root', auth_type='userpass', creds=creds, **self.vo)

    def testx509(self):
        """ CLIENTS (BASECLIENT): authenticate with x509."""
        creds = {'client_cert': self.usercert,
                 'client_key': self.userkey}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, **self.vo)

    @raises(CannotAuthenticate)
    def testx509NonExistingCert(self):
        """ CLIENTS (BASECLIENT): authenticate with x509 with missing certificate."""
        creds = {'client_cert': '/opt/rucio/etc/web/notthere.crt'}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds, **self.vo)

    @raises(ClientProtocolNotSupported)
    def testClientProtocolNotSupported(self):
        """ CLIENTS (BASECLIENT): try to pass an host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='localhost', auth_host='junk://localhost', account='root', auth_type='userpass', creds=creds, **self.vo)


class TestRucioClients(object):
    """ To test Clients"""

    def setup(self):
        '''
        setup
        '''
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        self.cacert = config_get('test', 'cacert')
        self.marker = '$> '

    def test_ping(self):
        """ PING (CLIENT): Ping Rucio """
        creds = {'username': 'ddmlab', 'password': 'secret'}

        client = Client(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds, **self.vo)

        print(client.ping())
