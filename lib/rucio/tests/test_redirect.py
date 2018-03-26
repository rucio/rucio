# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017

from nose.tools import assert_in

from rucio.client.baseclient import BaseClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get
from rucio.common.utils import generate_uuid
from rucio.tests.common import execute


class TestReplicaHeaderRedirection:

    def __init__(self):
        self.cacert = config_get('test', 'cacert')
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')

        self.base_client = BaseClient()
        self.token = self.base_client.headers['X-Rucio-Auth-Token']
        self.replica_client = ReplicaClient()

    def test_replica_header_redirection(self):
        """ REDIRECT: header to replica"""
        tmp_scope = 'mock'
        tmp_name = 'file_%s' % generate_uuid()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" -X GET %s/redirect/%s/%s''' % (self.cacert,
                                                                                                 self.token,
                                                                                                 self.host,
                                                                                                 tmp_scope,
                                                                                                 tmp_name)
        _, out, _ = execute(cmd)
        assert_in('404 Not Found', out)

        self.replica_client.add_replicas(rse='MOCK', files=[{'scope': tmp_scope,
                                                             'name': tmp_name,
                                                             'bytes': 1,
                                                             'adler32': '0cc737eb'}])
        self.replica_client.add_replicas(rse='MOCK3', files=[{'scope': tmp_scope,
                                                              'name': tmp_name,
                                                              'bytes': 1,
                                                              'adler32': '0cc737eb'}])
        _, out, _ = execute(cmd)
        assert_in('303 See Other', out)
        assert_in('Location: https://mock', out)


class TestReplicaMetalinkRedirection:

    def __init__(self):
        self.cacert = config_get('test', 'cacert')
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')

        self.base_client = BaseClient()
        self.token = self.base_client.headers['X-Rucio-Auth-Token']
        self.replica_client = ReplicaClient()

    def test_replica_meta_redirection(self):
        """ REDIRECT: metalink to replica"""
        tmp_scope = 'mock'
        tmp_name = 'file_%s' % generate_uuid()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" -X GET %s/redirect/%s/%s''' % (self.cacert,
                                                                                                 self.token,
                                                                                                 self.host,
                                                                                                 tmp_scope,
                                                                                                 tmp_name)
        _, out, _ = execute(cmd)
        assert_in('404 Not Found', out)

        self.replica_client.add_replicas(rse='MOCK', files=[{'scope': tmp_scope,
                                                             'name': tmp_name,
                                                             'bytes': 1,
                                                             'adler32': '0cc737eb'}])
        self.replica_client.add_replicas(rse='MOCK3', files=[{'scope': tmp_scope,
                                                              'name': tmp_name,
                                                              'bytes': 1,
                                                              'adler32': '0cc737eb'}])
        _, out, _ = execute(cmd)
        assert_in('303 See Other', out)
        assert_in('Link: </redirect/%s/%s/metalink' % (tmp_scope,
                                                       tmp_name), out)

        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" -X GET %s/redirect/%s/%s/metalink''' % (self.cacert,
                                                                                                          self.token,
                                                                                                          self.host,
                                                                                                          tmp_scope,
                                                                                                          tmp_name)
        _, out, _ = execute(cmd)
        assert_in('200 OK', out)
        assert_in('<?xml', out)
        assert_in('<metalink', out)
        assert_in('<url location="MOCK"', out)
        assert_in('<url location="MOCK3"', out)
