# -*- coding: utf-8 -*-
# Copyright CERN since 2020
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

from rucio.client import client
from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.distance import add_distance
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, del_rse, add_protocol, add_rse_attribute
from rucio.core.rule import add_rule
from rucio.daemons.conveyor.common import next_transfers_to_submit
from rucio.tests.common import rse_name_generator
from rucio.tests.common_server import get_vo


@pytest.mark.noparallel(reason='fails when run in parallel')
class TestS3(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.root = InternalAccount('root', **self.vo)

        # add an S3 storage with a replica
        self.rc = client.ReplicaClient()
        self.rses3 = rse_name_generator()
        self.rses3_id = add_rse(self.rses3, **self.vo)
        add_protocol(self.rses3_id, {'scheme': 'https',
                                     'hostname': 'fake-rucio.s3-eu-south-8.amazonaws.com',
                                     'port': 443,
                                     'prefix': '/',
                                     'impl': 'rucio.rse.protocols.gfal.NoRename',
                                     'domains': {
                                         'lan': {'read': 1, 'write': 1, 'delete': 1},
                                         'wan': {'read': 1, 'write': 1, 'delete': 1, 'third_party_copy_read': 1, 'third_party_copy_write': 1}}})
        add_rse_attribute(rse_id=self.rses3_id, key='sign_url', value='s3')
        add_rse_attribute(rse_id=self.rses3_id, key='fts', value='localhost')
        self.files3 = [{'scope': InternalScope('mock', **self.vo), 'name': 'file-on-aws',
                        'bytes': 1234, 'adler32': 'deadbeef', 'meta': {'events': 123}}]
        add_replicas(rse_id=self.rses3_id, files=self.files3, account=self.root)

        # add a non-S3 storage with a replica
        self.rsenons3 = rse_name_generator()
        self.rsenons3_id = add_rse(self.rsenons3, **self.vo)
        add_protocol(self.rsenons3_id, {'scheme': 'https',
                                        'hostname': 'somestorage.ch',
                                        'port': 1094,
                                        'prefix': '/my/prefix',
                                        'impl': 'rucio.rse.protocols.gfal.Default',
                                        'domains': {
                                            'lan': {'read': 1, 'write': 1, 'delete': 1},
                                            'wan': {'read': 1, 'write': 1, 'delete': 1, 'third_party_copy_read': 1, 'third_party_copy_write': 1}}})
        add_rse_attribute(rse_id=self.rsenons3_id, key='fts', value='localhost')
        self.filenons3 = [{'scope': InternalScope('mock', **self.vo), 'name': 'file-on-storage',
                           'bytes': 1234, 'adler32': 'deadbeef', 'meta': {'events': 321}}]
        add_replicas(rse_id=self.rsenons3_id, files=self.filenons3, account=self.root)

        # set the distance both ways
        add_distance(self.rses3_id, self.rsenons3_id, ranking=1, agis_distance=1, geoip_distance=1)
        add_distance(self.rsenons3_id, self.rses3_id, ranking=1, agis_distance=1, geoip_distance=1)

    def tearDown(self):
        delete_replicas(rse_id=self.rses3_id, files=self.files3)
        delete_replicas(rse_id=self.rsenons3_id, files=self.filenons3)
        del_rse(self.rses3_id)
        del_rse(self.rsenons3_id)

    def test_s3s_fts_src(self):
        """ S3: TPC a file from S3 to storage """

        expected_src_url = 's3s://fake-rucio.s3-eu-south-8.amazonaws.com:443/mock/69/3b/file-on-aws'
        expected_dst_url = 'https://somestorage.ch:1094/my/prefix/mock/69/3b/file-on-aws'

        rule_id = add_rule(dids=self.files3, account=self.root, copies=1, rse_expression=self.rsenons3,
                           grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        [[_, [transfer_path]]] = next_transfers_to_submit(rses=[self.rsenons3_id]).items()
        assert transfer_path[0].rws.rule_id == rule_id[0]
        assert transfer_path[0].legacy_sources[0][1] == expected_src_url
        assert transfer_path[0].dest_url == expected_dst_url

    def test_s3s_fts_dst(self):
        """ S3: TPC a file from storage to S3 """

        expected_src_url = 'https://somestorage.ch:1094/my/prefix/mock/ab/01/file-on-storage?copy_mode=push'
        expected_dst_url = 's3s://fake-rucio.s3-eu-south-8.amazonaws.com:443/mock/ab/01/file-on-storage'

        rule_id = add_rule(dids=self.filenons3, account=self.root, copies=1, rse_expression=self.rses3,
                           grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        [[_, [transfer_path]]] = next_transfers_to_submit(rses=[self.rses3_id]).items()
        assert transfer_path[0].rws.rule_id == rule_id[0]
        assert transfer_path[0].legacy_sources[0][1] == expected_src_url
        assert transfer_path[0].dest_url == expected_dst_url
