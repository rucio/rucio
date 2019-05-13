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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017-2019
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

try:
    # PY3
    from urllib import urlencode
except ImportError:
    # PY3
    from urllib.parse import urlencode

from nose.tools import assert_equal, assert_in, assert_not_in
from paste.fixture import TestApp

from rucio.client import ReplicaClient
from rucio.core.config import set as config_set
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_rse, add_rse_attribute, del_rse, add_protocol
from rucio.tests.common import rse_name_generator
from rucio.web.rest.redirect import APP as redirect_app


class TestROOTProxy(object):

    def setup(self):

        self.rc = ReplicaClient()

        self.client_location_without_proxy = {'ip': '192.168.0.1',
                                              'fqdn': 'anomalous-materials.blackmesa.com',
                                              'site': 'BLACKMESA1'}
        self.rse_without_proxy = rse_name_generator()
        add_rse(self.rse_without_proxy)
        add_rse_attribute(rse=self.rse_without_proxy,
                          key='site',
                          value='BLACKMESA1')

        self.client_location_with_proxy = {'ip': '10.0.1.1',
                                           'fqdn': 'test-chamber.aperture.com',
                                           'site': 'APERTURE1'}
        self.rse_with_proxy = rse_name_generator()
        add_rse(self.rse_with_proxy)
        add_rse_attribute(rse=self.rse_with_proxy,
                          key='site',
                          value='APERTURE1')

        # APERTURE1 site has an internal proxy
        config_set('root-proxy-internal', 'APERTURE1', 'proxy.aperture.com:1094')

        self.files = [{'scope': 'mock',
                       'name': 'half-life_%s' % i,
                       'bytes': 1234,
                       'adler32': 'deadbeef',
                       'meta': {'events': 666}} for i in range(1, 4)]
        for rse in [self.rse_with_proxy, self.rse_without_proxy]:
            add_replicas(rse=rse,
                         files=self.files,
                         account='root',
                         ignore_availability=True)

        add_protocol(self.rse_without_proxy, {'scheme': 'root',
                                              'hostname': 'root.blackmesa.com',
                                              'port': 1409,
                                              'prefix': '//training/facility/',
                                              'impl': 'rucio.rse.protocols.xrootd.Default',
                                              'domains': {
                                                  'lan': {'read': 1,
                                                          'write': 1,
                                                          'delete': 1},
                                                  'wan': {'read': 1,
                                                          'write': 1,
                                                          'delete': 1}}})

        add_protocol(self.rse_with_proxy, {'scheme': 'root',
                                           'hostname': 'root.aperture.com',
                                           'port': 1409,
                                           'prefix': '//test/chamber/',
                                           'impl': 'rucio.rse.protocols.xrootd.Default',
                                           'domains': {
                                               'lan': {'read': 1,
                                                       'write': 1,
                                                       'delete': 1},
                                               'wan': {'read': 1,
                                                       'write': 1,
                                                       'delete': 1}}})

    def tearDown(self):
        for rse in [self.rse_with_proxy, self.rse_without_proxy]:
            delete_replicas(rse=rse, files=self.files)
        del_rse(self.rse_with_proxy)
        del_rse(self.rse_without_proxy)

    def test_client_list_replicas(self):
        """ ROOT (CLIENT): Test internal proxy prepend """

        #  no proxy involved
        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     rse_expression=self.rse_without_proxy,
                                                     client_location=self.client_location_without_proxy)]

        expected_pfns = ['root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1',
                         'root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2',
                         'root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3']
        found_pfns = [replica['pfns'].keys()[0] for replica in replicas]
        assert_equal(sorted(found_pfns), sorted(expected_pfns))

        #  outgoing proxy needs to be prepended
        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     rse_expression=self.rse_without_proxy,
                                                     client_location=self.client_location_with_proxy)]

        expected_pfns = ['root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1',
                         'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2',
                         'root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3']
        found_pfns = [replica['pfns'].keys()[0] for replica in replicas]
        assert_equal(sorted(found_pfns), sorted(expected_pfns))

        # outgoing proxy at destination does not matter
        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     rse_expression=self.rse_with_proxy,
                                                     client_location=self.client_location_without_proxy)]

        expected_pfns = ['root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1',
                         'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2',
                         'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3']
        found_pfns = [replica['pfns'].keys()[0] for replica in replicas]
        assert_equal(sorted(found_pfns), sorted(expected_pfns))

        # outgoing proxy does not matter when staying at site
        replicas = [r for r in self.rc.list_replicas(dids=[{'scope': 'mock',
                                                            'name': f['name'],
                                                            'type': 'FILE'} for f in self.files],
                                                     rse_expression=self.rse_with_proxy,
                                                     client_location=self.client_location_with_proxy)]
        expected_pfns = ['root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1',
                         'root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2',
                         'root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3']
        found_pfns = [replica['pfns'].keys()[0] for replica in replicas]
        assert_equal(sorted(found_pfns), sorted(expected_pfns))

    def test_redirect_metalink_list_replicas(self):
        """ ROOT (REDIRECT REST): Test internal proxy prepend with metalink"""
        mw = []

        # default behaviour - no location -> no proxy
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_1/metalink', expect_errors=True)
        assert_in('root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1', res.body)
        assert_not_in('proxy', res.body)
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_2/metalink', expect_errors=True)
        assert_in('root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2', res.body)
        assert_not_in('proxy', res.body)
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_3/metalink', expect_errors=True)
        assert_in('root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3', res.body)
        assert_not_in('proxy', res.body)

        # site without proxy
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_1/metalink?%s' % urlencode(self.client_location_without_proxy),
                                                      expect_errors=True)
        assert_in('root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1', res.body)
        assert_not_in('proxy', res.body)
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_2/metalink?%s' % urlencode(self.client_location_without_proxy),
                                                      expect_errors=True)
        assert_in('root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2', res.body)
        assert_not_in('proxy', res.body)
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_3/metalink?%s' % urlencode(self.client_location_without_proxy),
                                                      expect_errors=True)
        assert_in('root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3', res.body)
        assert_not_in('proxy', res.body)

        # at location with outgoing proxy, prepend for wan replica
        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_1/metalink?%s' % urlencode(self.client_location_with_proxy),
                                                      expect_errors=True)
        assert_in('root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c9/df/half-life_1', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/c9/df/half-life_1', res.body)

        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_2/metalink?%s' % urlencode(self.client_location_with_proxy),
                                                      expect_errors=True)
        assert_in('root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/c1/8d/half-life_2', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/c1/8d/half-life_2', res.body)

        res = TestApp(redirect_app.wsgifunc(*mw)).get('/mock/half-life_3/metalink?%s' % urlencode(self.client_location_with_proxy),
                                                      expect_errors=True)
        assert_in('root://proxy.aperture.com:1094//root://root.blackmesa.com:1409//training/facility/mock/16/30/half-life_3', res.body)
        assert_in('root://root.aperture.com:1409//test/chamber/mock/16/30/half-life_3', res.body)
