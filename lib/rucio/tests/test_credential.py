# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2018
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from nose.tools import assert_equal, assert_raises, assert_in, assert_greater

from rucio.client import client
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import UnsupportedOperation
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.credential import get_signed_url
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, del_rse, add_protocol, add_rse_attribute
from rucio.tests.common import rse_name_generator


class TestCredential(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        self.rc = client.ReplicaClient()
        self.rse1 = rse_name_generator()
        self.rse2 = rse_name_generator()
        self.rse1_id = add_rse(self.rse1, **self.vo)
        self.rse2_id = add_rse(self.rse2, **self.vo)

        add_protocol(self.rse1_id, {'scheme': 'https',
                                    'hostname': 'storage.googleapis.com',
                                    'port': 443,
                                    'prefix': '/atlas-europe-west1/',
                                    'impl': 'rucio.rse.protocols.gfal.Default',
                                    'domains': {
                                        'lan': {'read': 1, 'write': 1, 'delete': 1},
                                        'wan': {'read': 1, 'write': 1, 'delete': 1, 'third_party_copy': 1}}})

        add_protocol(self.rse2_id, {'scheme': 'https',
                                    'hostname': 'storage.googleapis.com',
                                    'port': 443,
                                    'prefix': '/atlas-europe-east1/',
                                    'impl': 'rucio.rse.protocols.gfal.Default',
                                    'domains': {
                                        'lan': {'read': 1, 'write': 1, 'delete': 1},
                                        'wan': {'read': 1, 'write': 1, 'delete': 1, 'third_party_copy': 1}}})

        # register some files there
        self.files = [{'scope': InternalScope('mock', **self.vo),
                       'name': 'file-on-gcs_%s' % i,
                       'bytes': 1234,
                       'adler32': 'deadbeef',
                       'meta': {'events': 666}} for i in range(0, 3)]
        root = InternalAccount('root', **self.vo)
        add_replicas(rse_id=self.rse1_id,
                     files=self.files,
                     account=root,
                     ignore_availability=True)
        add_replicas(rse_id=self.rse2_id,
                     files=self.files,
                     account=root,
                     ignore_availability=True)

        def tearDown(self):
            delete_replicas(rse_id=self.rse1_id, files=self.files)
            delete_replicas(rse_id=self.rse2_id, files=self.files)
            del_rse(rse_id=self.rse1_id)
            del_rse(rse_id=self.rse2_id)

    def test_sign_url_gcs(self):
        """ CREDENTIAL: Sign a URL for Google Cloud Storage """

        assert_raises(UnsupportedOperation, get_signed_url, self.rse1_id, 'fake-service', 'read', 'http://dummy')

        assert_raises(UnsupportedOperation, get_signed_url, self.rse1_id, 'gcs', 'transmogrify', 'http://dummy')

        assert_raises(UnsupportedOperation, get_signed_url, self.rse1_id, 'gcs', 'read', None)

        assert_raises(UnsupportedOperation, get_signed_url, self.rse1_id, 'gcs', 'read', '')

        assert_equal(get_signed_url(self.rse1_id, 'gcs', 'read', 'http://storage/directory/file', lifetime=None),
                     'https://storage.googleapis.com/directory/file?GoogleAccessId=rucio-test@rucio-test'
                     '.iam.gserviceaccount.com&Expires=0&Signature=u9cBWowYX22sAyApH5YySD9h0m%2FbIPLHLgY'
                     '0Db%2BQ4a0wICQ2PZzUfTuHXQF8dUbMJG04VH90U5EMzYg3qSUGyfnp6Jptnvgivf7iSHepJsYhyAYSBGs'
                     'bvTOqf%2BXMQHR5VTh06G8WriZPV2OgSJ61c8qY7k8h0ju4bwcdDMFD2CT933KsnYSVatLN3EfORonLLZv'
                     'Ydgf0WCQjUcVKRv8zY65HJS6ZKoCjhOqNBJNlpI6uR54MhmLN2CJWch1MnLIdO6bKfDup%2Bzkt8e9Xe9S'
                     '8pTeva5cN8ZFlMkeCz7JvNkVJb1KPhI1XHPWyfuPUa2ALHh9wAD2yFSOU3cDiORFE6A%3D%3D')

        assert_equal(get_signed_url(self.rse1_id, 'gcs', 'write', 'http://storage/directory/file', lifetime=None),
                     'https://storage.googleapis.com/directory/file?GoogleAccessId=rucio-test@rucio-test'
                     '.iam.gserviceaccount.com&Expires=0&Signature=Gn%2FL0%2FjGkBIdpHZ9bKw7tvqRCdslC11gt'
                     'jbLk5AG2jA4Ywd6mTvOinUB%2BZxHY2I3XzEuMfyMnFj0vfXSemN6XmmcQkiQBhl6P3zr0GrOuO4y0xjKT'
                     'am1MijMKLKFS9pZ6BBYrFgwKcYUcGJmVpq0Fo%2Bl5pLovBKhJbi3RE0YbGTCDA5UEM6WuWLMcQiY8smfK'
                     '6EH9bW5tAEs70vOwNNPPUm%2FbcNKnR4z6jqThXw2mn375L02SRPx1qQ853sZKHng6O4ydm%2BSW8i7rb1'
                     '%2BnqImWDOdvmcLIZzc6x9l6b7ETOqSL2OqOCStpBHPzpQU0spgJS96IB09uGRQum1Ej2ui5g%3D%3D')

        assert_equal(get_signed_url(self.rse1_id, 'gcs', 'delete', 'http://storage/directory/file', lifetime=None),
                     'https://storage.googleapis.com/directory/file?GoogleAccessId=rucio-test@rucio-test'
                     '.iam.gserviceaccount.com&Expires=0&Signature=FVDNroX1epdTCv%2BC74o%2B8uWyvJXrqiIWg'
                     'kdcedaOoryhRMjuv%2FVdKecnhViY%2BGOP%2B0CoI1uFOHBz%2B%2Bm10U9A3i%2B1v7AZRN5L6nbbS%2'
                     'BJTk4oiSBMJ3FpNT9knbOVd4aSPdiBwfTybwpkWSzEb8cKQsqzrGZk4hVffipMOKkxj7UgMe%2F0DiwqyF'
                     'o3NZsey12b9TG2xPVCZ5mJdIvJY0E5KiqEGXVCVChEhecZEyP0cUxjs8xM%2BxhOJ%2BioPQzRsFwVKtVv'
                     'LXestniEGBMY8SY4UuthQVO1Kmq2hg30KcsgXpLzAFheK1tz0GunqPU7%2BYACZMuHj1Hp%2BTnvKNxVuJ'
                     '5MT5g%3D%3D')

    def test_list_replicas_sign_url(self):
        """ CREDENTIAL: List replicas for an RSE where signature is enabled """

        add_rse_attribute(rse_id=self.rse1_id, key='sign_url', value='gcs')
        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     rse_expression=self.rse1)]
        found_pfns = [list(replica['pfns'].keys())[0] for replica in replicas]
        for pfn in found_pfns:
            assert_in('&Signature=', pfn)
            assert_greater(len(pfn), 120)

        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     rse_expression=self.rse2)]
        found_pfns = [list(replica['pfns'].keys())[0] for replica in replicas]
        expected_pfns = ['https://storage.googleapis.com:443/atlas-europe-east1/mock/04/92/file-on-gcs_0',
                         'https://storage.googleapis.com:443/atlas-europe-east1/mock/c6/5f/file-on-gcs_1',
                         'https://storage.googleapis.com:443/atlas-europe-east1/mock/03/eb/file-on-gcs_2']
        assert_equal(sorted(found_pfns), sorted(expected_pfns))
