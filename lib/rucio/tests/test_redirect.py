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

import unittest

import pytest

from rucio.client.baseclient import BaseClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid
from rucio.tests.common import execute, get_long_vo


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestReplicaHeaderRedirection(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo_header = '-H "X-Rucio-VO: %s"' % get_long_vo()
        else:
            self.vo_header = ''

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
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" %s -X GET %s/redirect/%s/%s''' % (self.cacert,
                                                                                                    self.token,
                                                                                                    self.vo_header,
                                                                                                    self.host,
                                                                                                    tmp_scope,
                                                                                                    tmp_name)
        _, out, _ = execute(cmd)
        assert '404 Not Found'.lower() in out.lower()

        self.replica_client.add_replicas(rse='MOCK', files=[{'scope': tmp_scope,
                                                             'name': tmp_name,
                                                             'bytes': 1,
                                                             'adler32': '0cc737eb'}])
        self.replica_client.add_replicas(rse='MOCK3', files=[{'scope': tmp_scope,
                                                              'name': tmp_name,
                                                              'bytes': 1,
                                                              'adler32': '0cc737eb'}])
        _, out, _ = execute(cmd)
        assert '303 See Other'.lower() in out.lower()
        assert 'Location: https://mock' in out


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestReplicaMetalinkRedirection(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo_header = '-H "X-Rucio-VO: %s"' % get_long_vo()
        else:
            self.vo_header = ''

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
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" %s -X GET %s/redirect/%s/%s' % (self.cacert,
                                                                                                  self.token,
                                                                                                  self.vo_header,
                                                                                                  self.host,
                                                                                                  tmp_scope,
                                                                                                  tmp_name)
        _, out, _ = execute(cmd)
        assert '404 Not Found'.lower() in out.lower()

        self.replica_client.add_replicas(rse='MOCK', files=[{'scope': tmp_scope,
                                                             'name': tmp_name,
                                                             'bytes': 1,
                                                             'adler32': '0cc737eb'}])
        self.replica_client.add_replicas(rse='MOCK3', files=[{'scope': tmp_scope,
                                                              'name': tmp_name,
                                                              'bytes': 1,
                                                              'adler32': '0cc737eb'}])
        _, out, _ = execute(cmd)
        assert '303 See Other'.lower() in out.lower()
        assert 'Link: </redirect/%s/%s/metalink' % (tmp_scope, tmp_name) in out

        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" %s -X GET %s/redirect/%s/%s/metalink' % (self.cacert,
                                                                                                           self.token,
                                                                                                           self.vo_header,
                                                                                                           self.host,
                                                                                                           tmp_scope,
                                                                                                           tmp_name)
        _, out, _ = execute(cmd)
        assert '200 OK'.lower() in out.lower()
        assert '<?xml' in out
        assert '<metalink' in out
        assert '<url location="MOCK"' in out
        assert '<url location="MOCK3"' in out
