# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

from nose.tools import assert_in

from rucio.client.baseclient import BaseClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get
from rucio.common.utils import generate_uuid
from rucio.tests.common import execute


class TestReplicaHttpRedirection:

    def setup(self):
        self.cacert = config_get('test', 'cacert')
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')
        self.marker = '$> '
        # get auth token
        self.base_client = BaseClient()
        self.token = self.base_client.headers['X-Rucio-Auth-Token']
        self.replica_client = ReplicaClient()

    def test_replica_http_redirection(self):
        """ REPLICA (redirection): http redirection to replica"""
        tmp_scope = 'mock'
        tmp_name = 'file_%s' % generate_uuid()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" -X GET %s/redirect/%s/%s''' % (self.cacert, self.token, self.host, tmp_scope, tmp_name)
        exitcode, out, err = execute(cmd)
        assert_in('404 Not Found', out)
        # add replicas
        self.replica_client.add_replicas(rse='MOCK', files=[{'scope': tmp_scope, 'name': tmp_name, 'bytes': 1L, 'adler32': '0cc737eb'}])
        self.replica_client.add_replicas(rse='MOCK3', files=[{'scope': tmp_scope, 'name': tmp_name, 'bytes': 1L, 'adler32': '0cc737eb'}])
        exitcode, out, err = execute(cmd)
        assert_in('302 Found', out)
        assert_in('Location: https://mock', out)
