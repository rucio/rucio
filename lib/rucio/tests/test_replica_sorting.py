# Copyright 2017-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from nose.tools import assert_equal, assert_in, assert_not_in

from rucio.client import ReplicaClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, del_rse, add_rse_attribute, add_protocol
from rucio.tests.common import rse_name_generator


class TestReplicaSorting(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

    def test_replica_sorting(self):
        """ REPLICA (CORE): Test the correct sorting of the replicas across WAN and LAN """

        self.rc = ReplicaClient()

        self.rse1 = 'APERTURE_%s' % rse_name_generator()
        self.rse2 = 'BLACKMESA_%s' % rse_name_generator()
        self.rse1_id = add_rse(self.rse1, **self.vo)
        self.rse2_id = add_rse(self.rse2, **self.vo)
        add_rse_attribute(rse_id=self.rse1_id, key='site', value='APERTURE')
        add_rse_attribute(rse_id=self.rse2_id, key='site', value='BLACKMESA')

        self.files = [{'scope': InternalScope('mock', **self.vo), 'name': 'element_0',
                       'bytes': 1234, 'adler32': 'deadbeef'}]
        root = InternalAccount('root', **self.vo)
        add_replicas(rse_id=self.rse1_id, files=self.files, account=root)
        add_replicas(rse_id=self.rse2_id, files=self.files, account=root)

        add_protocol(self.rse1_id, {'scheme': 'root',
                                    'hostname': 'root.aperture.com',
                                    'port': 1409,
                                    'prefix': '//test/chamber/',
                                    'impl': 'rucio.rse.protocols.xrootd.Default',
                                    'domains': {
                                        'lan': {'read': 1, 'write': 1, 'delete': 1},
                                        'wan': {'read': 1, 'write': 1, 'delete': 1}}})
        add_protocol(self.rse1_id, {'scheme': 'davs',
                                    'hostname': 'davs.aperture.com',
                                    'port': 443,
                                    'prefix': '/test/chamber/',
                                    'impl': 'rucio.rse.protocols.gfal.Default',
                                    'domains': {
                                        'lan': {'read': 2, 'write': 2, 'delete': 2},
                                        'wan': {'read': 2, 'write': 2, 'delete': 2}}})
        add_protocol(self.rse1_id, {'scheme': 'gsiftp',
                                    'hostname': 'gsiftp.aperture.com',
                                    'port': 8446,
                                    'prefix': '/test/chamber/',
                                    'impl': 'rucio.rse.protocols.gfal.Default',
                                    'domains': {
                                        'lan': {'read': 0, 'write': 0, 'delete': 0},
                                        'wan': {'read': 3, 'write': 3, 'delete': 3}}})

        add_protocol(self.rse2_id, {'scheme': 'gsiftp',
                                    'hostname': 'gsiftp.blackmesa.com',
                                    'port': 8446,
                                    'prefix': '/lambda/complex/',
                                    'impl': 'rucio.rse.protocols.gfal.Default',
                                    'domains': {
                                        'lan': {'read': 2, 'write': 2, 'delete': 2},
                                        'wan': {'read': 1, 'write': 1, 'delete': 1}}})
        add_protocol(self.rse2_id, {'scheme': 'davs',
                                    'hostname': 'davs.blackmesa.com',
                                    'port': 443,
                                    'prefix': '/lambda/complex/',
                                    'impl': 'rucio.rse.protocols.gfal.Default',
                                    'domains': {
                                        'lan': {'read': 0, 'write': 0, 'delete': 0},
                                        'wan': {'read': 2, 'write': 2, 'delete': 2}}})
        add_protocol(self.rse2_id, {'scheme': 'root',
                                    'hostname': 'root.blackmesa.com',
                                    'port': 1409,
                                    'prefix': '//lambda/complex/',
                                    'impl': 'rucio.rse.protocols.xrootd.Default',
                                    'domains': {
                                        'lan': {'read': 1, 'write': 1, 'delete': 1},
                                        'wan': {'read': 3, 'write': 3, 'delete': 3}}})

        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     schemes=['root', 'gsiftp', 'davs'],
                                                     client_location={'site': 'APERTURE'})]
        pfns = [r['pfns'] for r in replicas][0]
        assert_equal(len(pfns.keys()), 5)
        assert_equal(pfns['root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0']['domain'], 'lan')
        assert_equal(pfns['root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0']['priority'], 1)
        assert_equal(pfns['davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0']['domain'], 'lan')
        assert_equal(pfns['davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0']['priority'], 2)
        assert_equal(pfns['gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0']['domain'], 'wan')
        assert_equal(pfns['gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0']['priority'], 3)
        assert_equal(pfns['davs://davs.blackmesa.com:443/lambda/complex/mock/58/b5/element_0']['domain'], 'wan')
        assert_equal(pfns['davs://davs.blackmesa.com:443/lambda/complex/mock/58/b5/element_0']['priority'], 4)
        assert_equal(pfns['root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0']['domain'], 'wan')
        assert_equal(pfns['root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0']['priority'], 5)

        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     schemes=['root', 'gsiftp', 'davs'],
                                                     client_location={'site': 'BLACKMESA'})]
        pfns = [r['pfns'] for r in replicas][0]
        assert_equal(len(pfns.keys()), 5)
        assert_equal(pfns['root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0']['domain'], 'lan')
        assert_equal(pfns['root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0']['priority'], 1)
        assert_equal(pfns['gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0']['domain'], 'lan')
        assert_equal(pfns['gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0']['priority'], 2)
        assert_equal(pfns['root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0']['domain'], 'wan')
        assert_equal(pfns['root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0']['priority'], 3)
        assert_equal(pfns['davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0']['domain'], 'wan')
        assert_equal(pfns['davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0']['priority'], 4)
        assert_equal(pfns['gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0']['domain'], 'wan')
        assert_equal(pfns['gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0']['priority'], 5)

        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     schemes=['root', 'gsiftp', 'davs'],
                                                     client_location={'site': 'XEN'})]
        pfns = [r['pfns'] for r in replicas][0]
        assert_equal(len(pfns.keys()), 6)
        # TODO: intractable until RSE sorting is enabled
        assert_equal(pfns['gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0']['domain'], 'wan')
        assert_in(pfns['gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0']['priority'], [1, 2])
        assert_equal(pfns['root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0']['domain'], 'wan')
        assert_in(pfns['root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0']['priority'], [1, 2])
        assert_equal(pfns['davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0']['domain'], 'wan')
        assert_in(pfns['davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0']['priority'], [3, 4])
        assert_equal(pfns['davs://davs.blackmesa.com:443/lambda/complex/mock/58/b5/element_0']['domain'], 'wan')
        assert_in(pfns['davs://davs.blackmesa.com:443/lambda/complex/mock/58/b5/element_0']['priority'], [3, 4])
        assert_equal(pfns['gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0']['domain'], 'wan')
        assert_in(pfns['gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0']['priority'], [5, 6])
        assert_equal(pfns['root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0']['domain'], 'wan')
        assert_in(pfns['root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0']['priority'], [5, 6])

        ml = self.rc.list_replicas(dids=[{'scope': 'mock',
                                          'name': f['name'],
                                          'type': 'FILE'} for f in self.files],
                                   schemes=['root', 'gsiftp', 'davs'],
                                   metalink=True,
                                   client_location={'site': 'APERTURE'})
        assert_in('domain="lan" priority="1" client_extract="false">root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0', ml)
        assert_in('domain="lan" priority="2" client_extract="false">davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="3" client_extract="false">gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="4" client_extract="false">davs://davs.blackmesa.com:443/lambda/complex/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="5" client_extract="false">root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0', ml)
        assert_not_in('priority="6"', ml)

        ml = self.rc.list_replicas(dids=[{'scope': 'mock',
                                          'name': f['name'],
                                          'type': 'FILE'} for f in self.files],
                                   schemes=['root', 'gsiftp', 'davs'],
                                   metalink=True,
                                   client_location={'site': 'BLACKMESA'})
        assert_in('domain="lan" priority="1" client_extract="false">root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0', ml)
        assert_in('domain="lan" priority="2" client_extract="false">gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="3" client_extract="false">root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="4" client_extract="false">davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="5" client_extract="false">gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0', ml)
        assert_not_in('priority="6"', ml)

        # TODO: intractable until RSE sorting is enabled
        # ml = self.rc.list_replicas(dids=[{'scope': 'mock',
        #                                   'name': f['name'],
        #                                   'type': 'FILE'} for f in self.files],
        #                            schemes=['root', 'gsiftp', 'davs'],
        #                            metalink=True,
        #                            client_location={'site': 'XEN'})
        # assert_in('domain="wan" priority="1">root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0', ml)
        # assert_in('domain="wan" priority="2">gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0', ml)
        # assert_in('domain="wan" priority="3">davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0', ml)
        # assert_in('domain="wan" priority="4">davs://davs.blackmesa.com:443/lambda/complex/mock/58/b5/element_0', ml)
        # assert_in('domain="wan" priority="5">gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0', ml)
        # assert_in('domain="wan" priority="6">root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0', ml)
        # assert_not_in('priority="7"', ml)

        # ensure correct handling of disabled protocols
        add_protocol(self.rse1_id, {'scheme': 'root',
                                    'hostname': 'root2.aperture.com',
                                    'port': 1409,
                                    'prefix': '//test/chamber/',
                                    'impl': 'rucio.rse.protocols.xrootd.Default',
                                    'domains': {
                                        'lan': {'read': 1, 'write': 1, 'delete': 1},
                                        'wan': {'read': 0, 'write': 0, 'delete': 0}}})

        ml = self.rc.list_replicas(dids=[{'scope': 'mock',
                                          'name': f['name'],
                                          'type': 'FILE'} for f in self.files],
                                   schemes=['root', 'gsiftp', 'davs'],
                                   metalink=True,
                                   client_location={'site': 'BLACKMESA'})
        assert_in('domain="lan" priority="1" client_extract="false">root://root.blackmesa.com:1409//lambda/complex/mock/58/b5/element_0', ml)
        assert_in('domain="lan" priority="2" client_extract="false">gsiftp://gsiftp.blackmesa.com:8446/lambda/complex/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="3" client_extract="false">root://root.aperture.com:1409//test/chamber/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="4" client_extract="false">davs://davs.aperture.com:443/test/chamber/mock/58/b5/element_0', ml)
        assert_in('domain="wan" priority="5" client_extract="false">gsiftp://gsiftp.aperture.com:8446/test/chamber/mock/58/b5/element_0', ml)
        assert_not_in('priority="6"', ml)

        delete_replicas(rse_id=self.rse1_id, files=self.files)
        delete_replicas(rse_id=self.rse2_id, files=self.files)
        del_rse(self.rse1_id)
        del_rse(self.rse2_id)
