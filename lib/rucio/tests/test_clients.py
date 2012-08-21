# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from os import remove

from nose.tools import raises

from rucio.client.baseclient import BaseClient
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.common.exception import CannotAuthenticate, ClientParameterMismatch, ClientProtocolNotSupported


class TestBaseClient():

    def setUp(self):
        build_database(echo=False)
        create_root_account()
        try:
            remove('/tmp/rucio/auth_token_root')
        except OSError, e:
            if e.args[0] != 2:
                raise e

    def tearDown(self):
        destroy_database(echo=False)

    def testUserpass(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

    @raises(CannotAuthenticate)
    def testUserpassWrongCreds(self):
        """ CLIENTS (BASECLIENT): try to authenticate with wrong username."""
        creds = {'username': 'wrong', 'password': 'secret'}
        BaseClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

#    @raises(NoAuthInformation)
#    def testUserpassNoCreds(self):
#        """ CLIENTS (BASECLIENT): try to authenticate without userpass credentials."""
#        BaseClient(rucio_host='localhost', auth_host='localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass')

#    @raises(NoAuthInformation)
#    def testUserpassNoAuthType(self):
#        """ CLIENTS (BASECLIENT): try to authenticate without auth_type."""
#        creds = {'username': 'wrong', 'password': 'secret'}
#        BaseClient(rucio_host='localhost', auth_host='localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', creds=creds)

    @raises(CannotAuthenticate)
    def testUserpassNoCACert(self):
        """ CLIENTS (BASECLIENT): authenticate with userpass without ca cert."""
        creds = {'username': 'wrong', 'password': 'secret'}
        BaseClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', auth_type='userpass', creds=creds)

    def testx509(self):
        """ CLIENTS (BASECLIENT): authenticate with x509."""
        creds = {'client_cert': '/opt/rucio/etc/web/client.crt'}
        BaseClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='x509', creds=creds)

    @raises(CannotAuthenticate)
    def testx509WrongCert(self):
        """ CLIENTS (BASECLIENT): try authenticate with userpass and wrong certificate."""
        creds = {'client_cert': '/opt/rucio/etc/web/ca.crt'}
        BaseClient(rucio_host='https://localhost', auth_host='https://localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='x509', creds=creds)

    @raises(CannotAuthenticate)
    def testx509NonExistingCert(self):
        """ CLIENTS (BASECLIENT): authenticate with x509 with not existing certificate."""
        creds = {'client_cert': '/opt/rucio/etc/web/notthere.crt'}
        BaseClient(rucio_host='localhost', auth_host='localhost', account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='x509', creds=creds)

    @raises(ClientParameterMismatch)
    def testSslRucioParameterMismatch(self):
        """ CLIENTS (BASECLIENT): try to specify mismatched ssl paramater for the rucio server."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='https://localhost', auth_host='localhost', account='root', rucio_use_ssl=False, auth_type='userpass', creds=creds)

    @raises(ClientParameterMismatch)
    def testSslRucioParameterMismatch2(self):
        """ CLIENTS (BASECLIENT): try to specify mismatched ssl paramater for the rucio server."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='http://localhost', auth_host='localhost', account='root', rucio_use_ssl=True, auth_type='userpass', creds=creds)

    @raises(ClientParameterMismatch)
    def testSslAuthParameterMismatch(self):
        """ CLIENTS (BASECLIENT): try to specify mismatched ssl paramater for the auth server."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='localhost', auth_host='https://localhost', account='root', auth_use_ssl=False, auth_type='userpass', creds=creds)

    @raises(ClientParameterMismatch)
    def testSslAuthParameterMismatch2(self):
        """ CLIENTS (BASECLIENT): try to specify mismatched ssl paramater for the auth server."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='localhost', auth_host='http://localhost', account='root', auth_use_ssl=True, auth_type='userpass', creds=creds)

    @raises(ClientProtocolNotSupported)
    def testClientProtocolNotSupported(self):
        """ CLIENTS (BASECLIENT): try to pass an url with a not supported protocol."""
        creds = {'username': 'ddmlab', 'password': 'secret'}
        BaseClient(rucio_host='localhost', auth_host='junk://localhost', account='root', auth_use_ssl=False, auth_type='userpass', creds=creds)


class TestRucioClients():

    def setUp(self):
        build_database(echo=False)
        create_root_account()
        self.marker = '$> '

    def tearDown(self):
        destroy_database(echo=False)

    def test_ping(self):
        """ PING (CLIENT): Ping Rucio """
        creds = {'username': 'ddmlab', 'password': 'secret'}
        from rucio.client import Client

        c = Client(rucio_host='localhost', rucio_port=443, auth_host='localhost', auth_port=443, account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

        print c.ping()
