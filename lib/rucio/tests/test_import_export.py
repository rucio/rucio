# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function

from nose.tools import assert_equal, assert_true
from paste.fixture import TestApp

from rucio.db.sqla.constants import RSEType
from rucio.client.importclient import ImportClient
from rucio.client.exportclient import ExportClient
from rucio.common.utils import render_json, parse_response
from rucio.core.distance import add_distance, get_distances, export_distances
from rucio.core.exporter import export_data
from rucio.core.importer import import_data
from rucio.core.rse import get_rse_id, add_rse, get_rse, add_protocol, get_rse_protocols, list_rse_attributes, get_rse_transfer_limits, get_rse_limits, set_rse_limits, set_rse_transfer_limits, add_rse_attribute, list_rses, export_rse
from rucio.tests.common import rse_name_generator
from rucio.web.rest.importer import APP as import_app
from rucio.web.rest.exporter import APP as export_app
from rucio.web.rest.authentication import APP as auth_app


class TestImporter(object):

    def setup(self):
        # New RSE
        self.new_rse = rse_name_generator()

        # RSE 1 that already exists
        self.old_rse_1 = rse_name_generator()
        add_rse(self.old_rse_1, availability=1)
        add_protocol(self.old_rse_1, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'impl'})
        self.old_rse_id_1 = get_rse_id(self.old_rse_1)
        set_rse_limits(rse=self.old_rse_1, name='limit1', value='10')
        set_rse_transfer_limits(rse=self.old_rse_1, activity='activity1', max_transfers=10)
        add_rse_attribute(rse=self.old_rse_1, key='attr1', value='test10')

        # RSE 2 that already exists
        self.old_rse_2 = rse_name_generator()
        add_rse(self.old_rse_2)
        self.old_rse_id_2 = get_rse_id(self.old_rse_2)

        # RSE 3 that already exists
        self.old_rse_3 = rse_name_generator()
        add_rse(self.old_rse_3)
        self.old_rse_id_3 = get_rse_id(self.old_rse_3)

        # Distance that already exists
        add_distance(self.old_rse_id_1, self.old_rse_id_2)

        self.data1 = {
            'rses': [{
                'rse': self.new_rse,
                'rse_type': 'TAPE',
                'availability': 5,
                'city': 'NewCity',
                'protocols': {
                    'protocols': [{
                        'scheme': 'scheme',
                        'hostname': 'hostname',
                        'port': 1000,
                        'impl': 'impl'
                    }]
                },
                'limits': {
                    'limit1': 0
                },
                'transfer_limits': {
                    'activity1': {
                        'unknown_rse_id': {
                            'max_transfers': 1
                        }
                    }
                },
                'attributes': {
                    'attr1': 'test'
                }
            }, {
                'rse': self.old_rse_1,
                'protocols': {
                    'protocols': [{
                        'scheme': 'scheme1',
                        'hostname': 'hostname1',
                        'port': 1000,
                        'prefix': 'prefix',
                        'impl': 'impl1'
                    }, {
                        'scheme': 'scheme2',
                        'hostname': 'hostname2',
                        'port': 1001,
                        'impl': 'impl'
                    }]
                },
                'limits': {
                    'limit1': 0,
                    'limit2': 2
                },
                'transfer_limits': {
                    'activity1': {
                        self.old_rse_id_1: {
                            'max_transfers': 1
                        }
                    },
                    'activity2': {
                        self.old_rse_id_1: {
                            'max_transfers': 2
                        }
                    }
                },
                'attributes': {
                    'attr1': 'test1',
                    'attr2': 'test2'
                }
            }],
            'distances': {
                self.old_rse_1: {
                    self.old_rse_2: {'src_rse_id': self.old_rse_id_1, 'dest_rse_id': self.old_rse_id_2, 'ranking': 10},
                    self.old_rse_3: {'src_rse_id': self.old_rse_id_1, 'dest_rse_id': self.old_rse_id_3, 'ranking': 4}
                }
            }
        }
        self.data2 = {'rses': [{'rse': self.new_rse}]}
        self.data3 = {'distances': {}}

    def test_importer_core(self):
        """ IMPORTER (CORE): test import. """
        import_data(data=self.data1)

        # RSE that had not existed before
        rse = get_rse(self.new_rse)
        assert_equal(rse['availability'], 5)
        assert_equal(rse['city'], 'NewCity')
        assert_equal(rse['rse_type'], RSEType.TAPE)

        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in get_rse_protocols(self.new_rse)['protocols']]
        assert_true({'scheme': 'scheme', 'hostname': 'hostname', 'port': 1000} in protocols)

        attributes = list_rse_attributes(rse=self.new_rse)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse=self.new_rse)
        assert_equal(limits['limit1'], 0)

        transfer_limits = get_rse_transfer_limits(rse=self.new_rse)
        assert_equal(transfer_limits['activity1'][get_rse_id(self.new_rse)]['max_transfers'], 1)

        # RSE 1 that already exists
        rse = get_rse(self.old_rse_1)
        assert_equal(rse['rse'], self.old_rse_1)

        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in get_rse_protocols(self.old_rse_1)['protocols']]
        assert_true({'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'prefix': 'prefix', 'impl': 'impl1'} in protocols)
        assert_true({'scheme': 'scheme2', 'hostname': 'hostname2', 'port': 1001, 'impl': 'impl', 'prefix': ''} in protocols)

        attributes = list_rse_attributes(rse=self.old_rse_1)
        assert_equal(attributes['attr1'], 'test1')
        assert_equal(attributes['attr2'], 'test2')

        limits = get_rse_limits(rse=self.old_rse_1)
        assert_equal(limits['limit1'], 0)
        assert_equal(limits['limit2'], 2)

        transfer_limits = get_rse_transfer_limits(rse=self.old_rse_1)
        assert_equal(transfer_limits['activity1'][get_rse_id(self.old_rse_1)]['max_transfers'], 1)
        assert_equal(transfer_limits['activity2'][get_rse_id(self.old_rse_1)]['max_transfers'], 2)

        # Distances
        distance = get_distances(self.old_rse_id_1, self.old_rse_id_2)[0]
        assert_equal(distance['ranking'], 10)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_3)[0]
        assert_equal(distance['ranking'], 4)

        import_data(data=self.data2)
        import_data(data=self.data3)

    def test_importer_client(self):
        """ IMPORTER (CLIENT): test import. """
        import_client = ImportClient()
        import_client.import_data(data=self.data1)

        # RSE that had not existed before
        rse = get_rse(self.new_rse)
        assert_equal(rse['availability'], 5)
        assert_equal(rse['city'], 'NewCity')
        assert_equal(rse['rse_type'], RSEType.TAPE)
        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in get_rse_protocols(self.new_rse)['protocols']]
        assert_true({'scheme': 'scheme', 'hostname': 'hostname', 'port': 1000} in protocols)

        attributes = list_rse_attributes(rse=self.new_rse)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse=self.new_rse)
        assert_equal(limits['limit1'], 0)

        transfer_limits = get_rse_transfer_limits(rse=self.new_rse)
        assert_equal(transfer_limits['activity1'][get_rse_id(self.new_rse)]['max_transfers'], 1)

        # RSE 1 that already exists
        rse = get_rse(self.old_rse_1)
        assert_equal(rse['rse'], self.old_rse_1)

        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in get_rse_protocols(self.old_rse_1)['protocols']]
        assert_true({'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'prefix': 'prefix', 'impl': 'impl1'} in protocols)
        assert_true({'scheme': 'scheme2', 'hostname': 'hostname2', 'port': 1001, 'impl': 'impl', 'prefix': ''} in protocols)

        attributes = list_rse_attributes(rse=self.old_rse_1)
        assert_equal(attributes['attr1'], 'test1')
        assert_equal(attributes['attr2'], 'test2')

        limits = get_rse_limits(rse=self.old_rse_1)
        assert_equal(limits['limit1'], 0)
        assert_equal(limits['limit2'], 2)

        transfer_limits = get_rse_transfer_limits(rse=self.old_rse_1)
        assert_equal(transfer_limits['activity1'][get_rse_id(self.old_rse_1)]['max_transfers'], 1)
        assert_equal(transfer_limits['activity2'][get_rse_id(self.old_rse_1)]['max_transfers'], 2)

        # Distances
        distance = get_distances(self.old_rse_id_1, self.old_rse_id_2)[0]
        assert_equal(distance['ranking'], 10)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_3)[0]
        assert_equal(distance['ranking'], 4)

        import_client.import_data(data=self.data2)
        import_client.import_data(data=self.data3)

    def test_importer_rest(self):
        """ IMPORTER (REST): test import. """
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data1))
        assert_equal(r2.status, 201)

        # RSE that not existed before
        rse = get_rse(self.new_rse)
        assert_equal(rse['availability'], 5)
        assert_equal(rse['city'], 'NewCity')
        assert_equal(rse['rse_type'], RSEType.TAPE)

        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in get_rse_protocols(self.new_rse)['protocols']]
        assert_true({'scheme': 'scheme', 'hostname': 'hostname', 'port': 1000} in protocols)

        attributes = list_rse_attributes(rse=self.new_rse)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse=self.new_rse)
        assert_equal(limits['limit1'], 0)

        transfer_limits = get_rse_transfer_limits(rse=self.new_rse)
        assert_equal(transfer_limits['activity1'][get_rse_id(self.new_rse)]['max_transfers'], 1)

        # RSE 1 that already existed before
        rse = get_rse(self.old_rse_1)
        assert_equal(rse['rse'], self.old_rse_1)

        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in get_rse_protocols(self.old_rse_1)['protocols']]
        assert_true({'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'prefix': 'prefix', 'impl': 'impl1'} in protocols)
        assert_true({'scheme': 'scheme2', 'hostname': 'hostname2', 'port': 1001, 'impl': 'impl', 'prefix': ''} in protocols)

        attributes = list_rse_attributes(rse=self.old_rse_1)
        assert_equal(attributes['attr1'], 'test1')
        assert_equal(attributes['attr2'], 'test2')

        limits = get_rse_limits(rse=self.old_rse_1)
        assert_equal(limits['limit1'], 0)
        assert_equal(limits['limit2'], 2)

        transfer_limits = get_rse_transfer_limits(rse=self.old_rse_1)
        assert_equal(transfer_limits['activity1'][get_rse_id(self.old_rse_1)]['max_transfers'], 1)
        assert_equal(transfer_limits['activity2'][get_rse_id(self.old_rse_1)]['max_transfers'], 2)

        # Distances
        distance = get_distances(self.old_rse_id_1, self.old_rse_id_2)[0]
        assert_equal(distance['ranking'], 10)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_3)[0]
        assert_equal(distance['ranking'], 4)

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data2))
        assert_equal(r2.status, 201)

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data3))
        assert_equal(r2.status, 201)


class TestExporter(object):

    def test_export_core(self):
        """ EXPORT (CORE): Test the export of data."""
        data = export_data()
        assert_equal(data['rses'], [export_rse(rse['rse']) for rse in list_rses()])
        assert_equal(data['distances'], export_distances())

    def test_export_client(self):
        """ EXPORT (CLIENT): Test the export of data."""
        export_client = ExportClient()
        data = render_json(**export_client.export_data())
        assert_true('rses' in data)
        assert_true('distances' in data)

    def test_export_rest(self):
        """ EXPORT (REST): Test the export of data."""
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        r2 = TestApp(export_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        rses = [export_rse(rse['rse']) for rse in list_rses()]
        assert_equal(r2.status, 200)
        assert_equal(r2.body, render_json(**{'rses': rses, 'distances': export_distances()}))


class TestExportImport(object):

    def test_export_import(self):
        """ IMPORT/EXPORT (REST): Test the export and import of data together to check same syntax."""
        # Setup new RSE, distance, attribute, limits
        new_rse = rse_name_generator()
        add_rse(new_rse)

        # Get token
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        # Export data
        r2 = TestApp(export_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        exported_data = parse_response(r2.body)

        # Import data
        r3 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**exported_data))
        assert_equal(r3.status, 201)
