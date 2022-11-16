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

from rucio.client.baseclient import BaseClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.utils import generate_uuid
from rucio.tests.common import execute, get_long_vo


class TestReplicaHeaderRedirection:

    def test_replica_header_redirection(self, rse_factory, replica_client):
        rse1, rse1_id = rse_factory.make_rse(scheme='https', protocol_impl='rucio.rse.protocols.mock.Default')
        rse2, rse2_id = rse_factory.make_rse(scheme='https', protocol_impl='rucio.rse.protocols.mock.Default')

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            vo_header = '-H "X-Rucio-VO: %s"' % get_long_vo()
        else:
            vo_header = ''

        cacert = config_get('test', 'cacert')
        host = config_get('client', 'rucio_host')

        base_client = BaseClient()
        token = base_client.headers['X-Rucio-Auth-Token']

        """ REDIRECT: header to replica"""
        tmp_scope = 'mock'
        tmp_name = 'file_%s' % generate_uuid()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" %s -X GET %s/redirect/%s/%s''' % (cacert,
                                                                                                    token,
                                                                                                    vo_header,
                                                                                                    host,
                                                                                                    tmp_scope,
                                                                                                    tmp_name)
        _, out, _ = execute(cmd)
        assert '404 Not Found'.lower() in out.lower()

        replica_client.add_replicas(rse=rse1, files=[{'scope': tmp_scope,
                                                      'name': tmp_name,
                                                      'bytes': 1,
                                                      'adler32': '0cc737eb'}])
        replica_client.add_replicas(rse=rse2, files=[{'scope': tmp_scope,
                                                      'name': tmp_name,
                                                      'bytes': 1,
                                                      'adler32': '0cc737eb'}])
        _, out, _ = execute(cmd)
        assert '303 See Other'.lower() in out.lower()
        assert f'Location: https://{rse1_id}.cern.ch' in out \
               or f'Location: https://{rse2_id}.cern.ch' in out


class TestReplicaMetalinkRedirection:

    def test_replica_meta_redirection(self, rse_factory, replica_client):
        rse1, _ = rse_factory.make_rse(scheme='https', protocol_impl='rucio.rse.protocols.mock.Default')
        rse2, _ = rse_factory.make_rse(scheme='https', protocol_impl='rucio.rse.protocols.mock.Default')

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            vo_header = '-H "X-Rucio-VO: %s"' % get_long_vo()
        else:
            vo_header = ''

        cacert = config_get('test', 'cacert')
        host = config_get('client', 'rucio_host')

        base_client = BaseClient()
        token = base_client.headers['X-Rucio-Auth-Token']

        """ REDIRECT: metalink to replica"""
        tmp_scope = 'mock'
        tmp_name = 'file_%s' % generate_uuid()
        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" %s -X GET %s/redirect/%s/%s' % (cacert,
                                                                                                  token,
                                                                                                  vo_header,
                                                                                                  host,
                                                                                                  tmp_scope,
                                                                                                  tmp_name)
        _, out, _ = execute(cmd)
        assert '404 Not Found'.lower() in out.lower()

        replica_client.add_replicas(rse=rse1, files=[{'scope': tmp_scope,
                                                      'name': tmp_name,
                                                      'bytes': 1,
                                                      'adler32': '0cc737eb'}])
        replica_client.add_replicas(rse=rse2, files=[{'scope': tmp_scope,
                                                      'name': tmp_name,
                                                      'bytes': 1,
                                                      'adler32': '0cc737eb'}])
        _, out, _ = execute(cmd)
        assert '303 See Other'.lower() in out.lower()
        assert 'Link: </redirect/%s/%s/metalink' % (tmp_scope, tmp_name) in out

        cmd = 'curl -s -i --cacert %s -H "X-Rucio-Auth-Token: %s" %s -X GET %s/redirect/%s/%s/metalink' % (cacert,
                                                                                                           token,
                                                                                                           vo_header,
                                                                                                           host,
                                                                                                           tmp_scope,
                                                                                                           tmp_name)
        _, out, _ = execute(cmd)
        assert '200 OK'.lower() in out.lower()
        assert '<?xml' in out
        assert '<metalink' in out
        assert f'<url location="{rse1}"' in out
        assert f'<url location="{rse2}"' in out
