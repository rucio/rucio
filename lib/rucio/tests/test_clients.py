'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2016
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
 - Joaquin Bogado, <jbogado@linti.unlp.edu.ar>, 2018
'''

from __future__ import print_function

from os import remove

from nose.tools import raises

from rucio.client.baseclient import BaseClient
from rucio.client.client import Client
from rucio.common.config import config_get
from rucio.common.utils import get_tmp_dir
from rucio.common.exception import CannotAuthenticate, ClientProtocolNotSupported


class TestBaseClient(object):
    """ To test Clients"""

    def setup(self):
        '''
        __init__
        '''
        self.cacert = config_get('test', 'cacert')
        self.usercert = config_get('test', 'usercert')
        try:
            remove(get_tmp_dir() + '/.rucio_root/auth_token_root')
        except OSError as error:
            if error.args[0] != 2:
                raise error

    def testUserpass(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds)

    @raises(CannotAuthenticate)
    def testUserpassWrongCreds(self):
        """ CLIENTS (BASECLIENT): try to authenticate with wrong username."""
        creds = {'username': 'wrong', 'password': 'secret'}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds)

    @raises(CannotAuthenticate)
    def testUserpassNoCACert(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass without ca cert."""
        creds = {'username': 'wrong', 'password': 'secret'}
        BaseClient(account='root', auth_type='userpass', creds=creds)

    def testx509(self):
        """ CLIENTS (BASECLIENT): authenticate with x509."""
        creds = {'client_cert': self.usercert}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds)

    @raises(CannotAuthenticate)
    def testx509NonExistingCert(self):
        """ CLIENTS (BASECLIENT): authenticate with x509 with missing certificate."""
        creds = {'client_cert': '/opt/rucio/etc/web/notthere.crt'}
        BaseClient(account='root', ca_cert=self.cacert, auth_type='x509', creds=creds)

    @raises(ClientProtocolNotSupported)
    def testClientProtocolNotSupported(self):
        """ CLIENTS (BASECLIENT): try to pass an host with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='localhost', auth_host='junk://localhost', account='root', auth_type='userpass', creds=creds)


class TestRucioClients(object):
    """ To test Clients"""

    def setup(self):
        '''
        setup
        '''
        self.cacert = config_get('test', 'cacert')
        self.marker = '$> '

    def test_ping(self):
        """ PING (CLIENT): Ping Rucio """
        creds = {'username': 'ddmlab', 'password': 'secret'}

        client = Client(account='root', ca_cert=self.cacert, auth_type='userpass', creds=creds)

        print(client.ping())
