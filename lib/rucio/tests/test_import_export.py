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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function

from copy import deepcopy
from nose.tools import assert_equal, assert_true, assert_raises
from paste.fixture import TestApp

from rucio.db.sqla import session, models
from rucio.db.sqla.constants import RSEType
from rucio.client.importclient import ImportClient
from rucio.client.exportclient import ExportClient
from rucio.common.exception import RSENotFound
from rucio.common.utils import render_json, parse_response
from rucio.core.distance import add_distance, get_distances, export_distances
from rucio.core.exporter import export_data, export_rses
from rucio.core.importer import import_data
from rucio.core.rse import get_rse_id, get_rse_name, add_rse, get_rse, add_protocol, get_rse_protocols, list_rse_attributes, get_rse_limits, set_rse_limits, add_rse_attribute, list_rses, export_rse, get_rse_attribute
from rucio.tests.common import rse_name_generator
from rucio.web.rest.importer import APP as import_app
from rucio.web.rest.exporter import APP as export_app
from rucio.web.rest.authentication import APP as auth_app


def check_rse(rse_name, test_data):
    rse_id = get_rse_id(rse=rse_name)
    rse = get_rse(rse_id=rse_id)
    assert_equal(rse['rse'], rse_name)
    assert_equal(rse['rse_type'], test_data[rse_name]['rse_type'])
    assert_equal(rse['region_code'], test_data[rse_name]['region_code'])
    assert_equal(rse['country_name'], test_data[rse_name]['country_name'])
    assert_equal(rse['time_zone'], test_data[rse_name]['time_zone'])
    assert_equal(rse['volatile'], test_data[rse_name]['volatile'])
    assert_equal(rse['deterministic'], test_data[rse_name]['deterministic'])
    assert_equal(rse['city'], test_data[rse_name]['city'])
    assert_equal(rse['staging_area'], test_data[rse_name]['staging_area'])
    assert_equal(rse['longitude'], test_data[rse_name]['longitude'])
    assert_equal(rse['latitude'], test_data[rse_name]['latitude'])
    assert_equal(rse['availability'], test_data[rse_name]['availability'])


def check_protocols(rse, test_data):
    rse_id = get_rse_id(rse=rse)
    protocols = get_rse_protocols(rse_id)
    assert_equal(test_data[rse]['lfn2pfn_algorithm'], get_rse_attribute('lfn2pfn_algorithm', rse_id=rse_id, use_cache=False)[0])
    assert_equal(test_data[rse]['verify_checksum'], get_rse_attribute('verify_checksum', rse_id=rse_id, use_cache=False)[0])
    assert_equal(test_data[rse]['availability_write'], protocols['availability_write'])
    assert_equal(test_data[rse]['availability_read'], protocols['availability_read'])
    assert_equal(test_data[rse]['availability_delete'], protocols['availability_delete'])
    protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in protocols['protocols']]
    for protocol in test_data[rse]['protocols']:
        assert_true({'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol.get('impl', ''), 'prefix': protocol.get('prefix', '')} in protocols)


def reset_rses():
    db_session = session.get_session()
    for rse in db_session.query(models.RSE).all():
        rse.deleted = False
        rse.deleted_at = None
        rse.save(session=db_session)
        add_rse_attribute(rse_id=rse['id'], key=rse['rse'], value=True, session=db_session)
    db_session.commit()


class TestImporter(object):

    def setup(self):
        # New RSE
        self.new_rse = rse_name_generator()

        # RSE 1 that already exists
        self.old_rse_1 = rse_name_generator()
        self.old_rse_id_1 = add_rse(self.old_rse_1, availability=1, region_code='DE', country_name='DE', deterministic=True, volatile=True, staging_area=True, time_zone='Europe', latitude='1', longitude='2')
        add_protocol(self.old_rse_id_1, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})
        add_protocol(self.old_rse_id_1, {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'})

        set_rse_limits(rse_id=self.old_rse_id_1, name='MaxBeingDeletedFiles', value='10')
        set_rse_limits(rse_id=self.old_rse_id_1, name='MinFreeSpace', value='10')
        add_rse_attribute(rse_id=self.old_rse_id_1, key='attr1', value='test10')
        add_rse_attribute(rse_id=self.old_rse_id_1, key='lfn2pfn_algorithm', value='test10')
        add_rse_attribute(rse_id=self.old_rse_id_1, key='verify_checksum', value=True)

        # RSE 2 that already exists
        self.old_rse_2 = rse_name_generator()
        self.old_rse_id_2 = add_rse(self.old_rse_2)

        # RSE 3 that already exists
        self.old_rse_3 = rse_name_generator()
        self.old_rse_id_3 = add_rse(self.old_rse_3)

        # RSE 4 that already exists
        self.old_rse_4 = rse_name_generator()
        self.old_rse_id_4 = add_rse(self.old_rse_4)

        # RSE 4 that already exists
        self.old_rse_4 = rse_name_generator()
        add_rse(self.old_rse_4)
        self.old_rse_id_4 = get_rse_id(self.old_rse_4)

        # Distance that already exists
        add_distance(self.old_rse_id_1, self.old_rse_id_2)

        self.data1 = {
            'rses': {
                self.new_rse: {
                    'rse_type': RSEType.TAPE,
                    'availability': 3,
                    'city': 'NewCity',
                    'region_code': 'CH',
                    'country_name': 'switzerland',
                    'staging_area': False,
                    'time_zone': 'Europe',
                    'latitude': 1,
                    'longitude': 2,
                    'deterministic': True,
                    'volatile': False,
                    'protocols': [{
                        'scheme': 'scheme',
                        'hostname': 'hostname',
                        'port': 1000,
                        'impl': 'impl'
                    }],
                    'attributes': {
                        'attr1': 'test'
                    },
                    'MinFreeSpace': 20000,
                    'lfn2pfn_algorithm': 'hash2',
                    'verify_checksum': False,
                    'availability_delete': True,
                    'availability_read': False,
                    'availability_write': True
                },
                self.old_rse_1: {
                    'rse_type': RSEType.TAPE,
                    'deterministic': False,
                    'volatile': False,
                    'region_code': 'US',
                    'country_name': 'US',
                    'staging_area': False,
                    'time_zone': 'Asia',
                    'longitude': 5,
                    'city': 'City',
                    'availability': 2,
                    'latitude': 10,
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
                    }],
                    'attributes': {
                        'attr1': 'test1',
                        'attr2': 'test2'
                    },
                    'MinFreeSpace': 10000,
                    'MaxBeingDeletedFiles': 1000,
                    'verify_checksum': False,
                    'lfn2pfn_algorithm': 'hash3',
                    'availability_delete': False,
                    'availability_read': False,
                    'availability_write': True
                },
                self.old_rse_2: {},
                self.old_rse_3: {}
            },
            'distances': {
                self.old_rse_1: {
                    self.old_rse_2: {'src_rse': self.old_rse_1, 'dest_rse': self.old_rse_2, 'ranking': 10},
                    self.old_rse_3: {'src_rse': self.old_rse_1, 'dest_rse': self.old_rse_3, 'ranking': 4}
                }
            }
        }

        self.data2 = {'rses': {self.new_rse: {'rse': self.new_rse}}}
        self.data3 = {'distances': {}}

    def tearDown(self):
        reset_rses()

    def test_importer_core(self):
        """ IMPORTER (CORE): test import. """
        import_data(data=deepcopy(self.data1))

        # RSE that had not existed before
        check_rse(self.new_rse, self.data1['rses'])
        check_protocols(self.new_rse, self.data1['rses'])

        new_rse_id = get_rse_id(rse=self.new_rse)

        attributes = list_rse_attributes(rse_id=new_rse_id)
        assert_equal(attributes['attr1'], 'test')
        limits = get_rse_limits(rse_id=new_rse_id)
        assert_equal(limits['MinFreeSpace'], 20000)

        # RSE 1 that already exists
        check_rse(self.old_rse_1, self.data1['rses'])

        # one protocol should be created, one should be updated
        check_protocols(self.old_rse_1, self.data1['rses'])

        # one protocol should be removed as it is not specified in the import data
        protocols = get_rse_protocols(self.old_rse_id_1)
        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
        assert_true({'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols)

        attributes = list_rse_attributes(rse_id=self.old_rse_id_1)
        assert_equal(attributes['attr1'], 'test1')
        assert_equal(attributes['attr2'], 'test2')

        limits = get_rse_limits(rse_id=self.old_rse_id_1)
        assert_equal(limits['MaxBeingDeletedFiles'], 1000)
        assert_equal(limits['MinFreeSpace'], 10000)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_2)[0]
        assert_equal(distance['ranking'], 10)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_3)[0]
        assert_equal(distance['ranking'], 4)

        # RSE 4 should be flagged as deleted as it is missing in the import data
        with assert_raises(RSENotFound):
            get_rse(rse_id=self.old_rse_id_4)

        import_data(data=self.data2)
        import_data(data=self.data3)

    def test_importer_client(self):
        """ IMPORTER (CLIENT): test import. """
        import_client = ImportClient()
        import_client.import_data(data=deepcopy(self.data1))

        # RSE that had not existed before
        check_rse(self.new_rse, self.data1['rses'])
        check_protocols(self.new_rse, self.data1['rses'])

        new_rse_id = get_rse_id(rse=self.new_rse)

        protocols = get_rse_protocols(self.old_rse_id_1)
        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
        assert_true({'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols)

        attributes = list_rse_attributes(rse_id=new_rse_id)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse_id=new_rse_id)
        assert_equal(limits['MinFreeSpace'], 20000)

        # RSE 1 that already exists
        check_rse(self.old_rse_1, self.data1['rses'])
        check_protocols(self.old_rse_1, self.data1['rses'])

        attributes = list_rse_attributes(rse_id=self.old_rse_id_1)
        assert_equal(attributes['attr1'], 'test1')
        assert_equal(attributes['attr2'], 'test2')

        limits = get_rse_limits(rse_id=self.old_rse_id_1)
        assert_equal(limits['MaxBeingDeletedFiles'], 1000)
        assert_equal(limits['MinFreeSpace'], 10000)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_2)[0]
        assert_equal(distance['ranking'], 10)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_3)[0]
        assert_equal(distance['ranking'], 4)

        with assert_raises(RSENotFound):
            get_rse(rse_id=self.old_rse_id_4)

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
        assert_equal(r2.status, 201, r2.body)

        # RSE that not existed before
        check_rse(self.new_rse, self.data1['rses'])
        check_protocols(self.new_rse, self.data1['rses'])

        new_rse_id = get_rse_id(rse=self.new_rse)

        protocols = get_rse_protocols(self.old_rse_id_1)
        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
        assert_true({'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols)

        attributes = list_rse_attributes(rse_id=new_rse_id)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse_id=new_rse_id)
        assert_equal(limits['MinFreeSpace'], 20000)

        # RSE 1 that already existed before
        check_rse(self.old_rse_1, self.data1['rses'])
        check_protocols(self.old_rse_1, self.data1['rses'])

        attributes = list_rse_attributes(rse_id=self.old_rse_id_1)
        assert_equal(attributes['attr1'], 'test1')
        assert_equal(attributes['attr2'], 'test2')

        limits = get_rse_limits(rse_id=self.old_rse_id_1)
        assert_equal(limits['MaxBeingDeletedFiles'], 1000)
        assert_equal(limits['MinFreeSpace'], 10000)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_2)[0]
        assert_equal(distance['ranking'], 10)

        distance = get_distances(self.old_rse_id_1, self.old_rse_id_3)[0]
        assert_equal(distance['ranking'], 4)

        with assert_raises(RSENotFound):
            get_rse(rse_id=self.old_rse_id_4)

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data2))
        assert_equal(r2.status, 201)

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data3))
        assert_equal(r2.status, 201)


class TestExporter(object):

    def test_export_core(self):
        """ EXPORT (CORE): Test the export of data."""
        data = export_data()
        assert_equal(data['rses'], export_rses())
        assert_equal(data['distances'], export_distances())

    def test_export_client(self):
        """ EXPORT (CLIENT): Test the export of data."""
        export_client = ExportClient()
        data = export_client.export_data()
        rses = {}
        for rse in list_rses():
            rse_name = rse['rse']
            rse_id = rse['id']
            rses[rse_name] = export_rse(rse_id=rse_id)
        assert_equal(data['rses'], parse_response(render_json(**rses)))
        assert_equal(data['distances'], parse_response(render_json(**export_distances())))

    def test_export_rest(self):
        """ EXPORT (REST): Test the export of data."""
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        r2 = TestApp(export_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        rses = export_rses()
        sanitised = {}
        for rse_id in rses:
            sanitised[get_rse_name(rse_id=rse_id)] = rses[rse_id]
        rses = sanitised

        assert_equal(r2.status, 200)
        assert_equal(r2.body, render_json(**{'rses': rses, 'distances': export_distances()}))


class TestExportImport(object):
    def tearDown(self):
        reset_rses()

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
