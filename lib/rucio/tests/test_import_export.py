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
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function

from copy import deepcopy
from nose.tools import assert_equal, assert_true, assert_raises, assert_in
from paste.fixture import TestApp

from rucio.db.sqla import session, models
from rucio.db.sqla.constants import RSEType, AccountType, IdentityType, AccountStatus
from rucio.client.importclient import ImportClient
from rucio.client.exportclient import ExportClient
from rucio.common.config import config_set, config_add_section, config_has_section, config_get, config_get_bool
from rucio.common.exception import RSENotFound
from rucio.common.types import InternalAccount
from rucio.common.utils import render_json, parse_response
from rucio.core.account import add_account, get_account
from rucio.core.distance import add_distance, get_distances
from rucio.core.exporter import export_data, export_rses
from rucio.core.identity import add_identity, list_identities, add_account_identity, list_accounts_for_identity
from rucio.core.importer import import_data, import_rses
from rucio.core.rse import get_rse_id, get_rse_name, add_rse, get_rse, add_protocol, get_rse_protocols, list_rse_attributes, get_rse_limits, set_rse_limits, add_rse_attribute, list_rses, export_rse, get_rse_attribute, del_rse
from rucio.tests.common import rse_name_generator
from rucio.web.rest.importer import APP as import_app
from rucio.web.rest.exporter import APP as export_app
from rucio.web.rest.authentication import APP as auth_app


def check_rse(rse_name, test_data, vo='def'):
    rse_id = get_rse_id(rse=rse_name, vo=vo)
    rse = get_rse(rse_id=rse_id)
    assert_equal(rse['rse'], rse_name)
    assert_equal(rse['vo'], vo)
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


def check_protocols(rse, test_data, vo='def'):
    rse_id = get_rse_id(rse=rse, vo=vo)
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


def test_active():
    db_session = session.get_session()
    if db_session.bind.dialect.name == 'sqlite':
        return False
    return True


class TestImporter(object):
    """ Tests the initial import method (hard-sync everything) """

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            self.vo_header = {'X-Rucio-VO': self.vo['vo']}
        else:
            self.vo = {}
            self.vo_header = {}

        if not config_has_section('importer'):
            config_add_section('importer')
        config_set('importer', 'rse_sync_method', 'hard')
        config_set('importer', 'attr_method', 'edit')
        config_set('importer', 'protocol_method', 'edit')

        # New RSE
        self.new_rse = rse_name_generator()

        # RSE 1 that already exists
        self.old_rse_1 = rse_name_generator()
        self.old_rse_id_1 = add_rse(self.old_rse_1, availability=1, region_code='DE', country_name='DE', deterministic=True, volatile=True, staging_area=True, time_zone='Europe', latitude='1', longitude='2', **self.vo)
        add_protocol(self.old_rse_id_1, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})
        add_protocol(self.old_rse_id_1, {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'})

        set_rse_limits(rse_id=self.old_rse_id_1, name='MaxBeingDeletedFiles', value='10')
        set_rse_limits(rse_id=self.old_rse_id_1, name='MinFreeSpace', value='10')
        add_rse_attribute(rse_id=self.old_rse_id_1, key='attr1', value='test10')
        add_rse_attribute(rse_id=self.old_rse_id_1, key='lfn2pfn_algorithm', value='test10')
        add_rse_attribute(rse_id=self.old_rse_id_1, key='verify_checksum', value=True)

        # RSE 2 that already exists
        self.old_rse_2 = rse_name_generator()
        self.old_rse_id_2 = add_rse(self.old_rse_2, **self.vo)

        # RSE 3 that already exists
        self.old_rse_3 = rse_name_generator()
        self.old_rse_id_3 = add_rse(self.old_rse_3, **self.vo)

        # RSE 4 that already exists
        self.old_rse_4 = rse_name_generator()
        self.old_rse_id_4 = add_rse(self.old_rse_4, **self.vo)

        # Distance that already exists
        add_distance(self.old_rse_id_1, self.old_rse_id_2)

        # Account 1 that already exists
        self.old_account_1 = InternalAccount(rse_name_generator(), **self.vo)
        add_account(self.old_account_1, AccountType.USER, email='test')

        # Account 2 that already exists
        self.old_account_2 = InternalAccount(rse_name_generator(), **self.vo)
        add_account(self.old_account_2, AccountType.USER, email='test')

        # Identity that should be removed
        self.identity_to_be_removed = rse_name_generator()
        add_identity(self.identity_to_be_removed, IdentityType.X509, email='email')
        add_account_identity(self.identity_to_be_removed, IdentityType.X509, self.old_account_2, 'email')

        # Identity that already exsits but should be added to the account
        self.identity_to_be_added_to_account = rse_name_generator()
        add_identity(self.identity_to_be_added_to_account, IdentityType.X509, email='email')

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
            },
            'accounts': [{
                'account': InternalAccount('new_account', **self.vo),
                'email': 'email',
                'identities': [{
                    'type': 'userpass',
                    'identity': 'username',
                    'password': 'password'
                }]
            }, {
                'account': InternalAccount('new_account2', **self.vo),
                'email': 'email'
            }, {
                'account': self.old_account_2,
                'email': 'new_email',
                'identities': [
                    {
                        'identity': self.identity_to_be_added_to_account,
                        'type': 'x509'
                    },
                    {
                        'type': 'userpass',
                        'identity': 'username2',
                        'password': 'password'
                    }
                ]
            }, {
                'account': InternalAccount('jdoe', **self.vo),
                'email': 'email'
            }]
        }

        self.data2 = {'rses': {self.new_rse: {'rse': self.new_rse}}}
        self.data3 = {'distances': {}}

    def tearDown(self):
        reset_rses()

    def check_accounts(self, test_accounts):
        db_identities = list_identities()
        for account in test_accounts:
            # check existence
            db_account = get_account(account=account['account'])
            assert_equal(db_account['account'], account['account'])

            # check properties
            email = account.get('email')
            if email:
                assert_equal(db_account['email'], account['email'])

            # check identities
            identities = account.get('identities')
            if identities:
                for identity in identities:
                    # check identity creation and identity-account association
                    identity_type = IdentityType.from_sym(identity['type'])
                    identity = identity['identity']
                    assert_in((identity, identity_type), db_identities)
                    accounts_for_identity = list_accounts_for_identity(identity, identity_type)
                    assert_in(account['account'], accounts_for_identity)

        # check removal of account
        account = get_account(self.old_account_1)
        assert_equal(account['status'], AccountStatus.DELETED)

        # check removal of identities
        accounts_for_identity = list_accounts_for_identity(self.identity_to_be_removed, IdentityType.X509)
        assert_true(account['account'] not in accounts_for_identity)

    def test_importer_core(self):
        """ IMPORTER (CORE): test import. """
        import_data(data=deepcopy(self.data1), **self.vo)

        # RSE that had not existed before
        check_rse(self.new_rse, self.data1['rses'], **self.vo)
        check_protocols(self.new_rse, self.data1['rses'], **self.vo)

        new_rse_id = get_rse_id(rse=self.new_rse, **self.vo)

        attributes = list_rse_attributes(rse_id=new_rse_id)
        assert_equal(attributes['attr1'], 'test')
        limits = get_rse_limits(rse_id=new_rse_id)
        assert_equal(limits['MinFreeSpace'], 20000)

        # RSE 1 that already exists
        check_rse(self.old_rse_1, self.data1['rses'], **self.vo)

        # one protocol should be created, one should be updated
        check_protocols(self.old_rse_1, self.data1['rses'], **self.vo)

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

        self.check_accounts(self.data1['accounts'])

        # RSE 4 should be flagged as deleted as it is missing in the import data
        with assert_raises(RSENotFound):
            get_rse(rse_id=self.old_rse_id_4)

        import_data(data=self.data2, **self.vo)
        import_data(data=self.data3, **self.vo)

    def test_importer_client(self):
        """ IMPORTER (CLIENT): test import. """
        import_client = ImportClient()
        import_client.import_data(data=deepcopy(self.data1))

        # RSE that had not existed before
        check_rse(self.new_rse, self.data1['rses'], **self.vo)
        check_protocols(self.new_rse, self.data1['rses'], **self.vo)

        new_rse_id = get_rse_id(rse=self.new_rse, **self.vo)

        protocols = get_rse_protocols(self.old_rse_id_1)
        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
        assert_true({'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols)

        attributes = list_rse_attributes(rse_id=new_rse_id)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse_id=new_rse_id)
        assert_equal(limits['MinFreeSpace'], 20000)

        # RSE 1 that already exists
        check_rse(self.old_rse_1, self.data1['rses'], **self.vo)
        check_protocols(self.old_rse_1, self.data1['rses'], **self.vo)

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

        self.check_accounts(self.data1['accounts'])

        # If the default sync method is not 'hard', RSE old_rse_id_4 should still be there
        # with assert_raises(RSENotFound):
        #     get_rse(rse_id=self.old_rse_id_4)

        import_client.import_data(data=self.data2)
        import_client.import_data(data=self.data3)

    def test_importer_rest(self):
        """ IMPORTER (REST): test import. """
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data1))
        assert_equal(r2.status, 201, r2.body)

        # RSE that not existed before
        check_rse(self.new_rse, self.data1['rses'], **self.vo)
        check_protocols(self.new_rse, self.data1['rses'], **self.vo)

        new_rse_id = get_rse_id(rse=self.new_rse, **self.vo)

        protocols = get_rse_protocols(self.old_rse_id_1)
        protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
        assert_true({'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols)

        attributes = list_rse_attributes(rse_id=new_rse_id)
        assert_equal(attributes['attr1'], 'test')

        limits = get_rse_limits(rse_id=new_rse_id)
        assert_equal(limits['MinFreeSpace'], 20000)

        # RSE 1 that already existed before
        check_rse(self.old_rse_1, self.data1['rses'], **self.vo)
        check_protocols(self.old_rse_1, self.data1['rses'], **self.vo)

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

        self.check_accounts(self.data1['accounts'])

        with assert_raises(RSENotFound):
            get_rse(rse_id=self.old_rse_id_4)

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data2))
        assert_equal(r2.status, 201)

        r2 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**self.data3))
        assert_equal(r2.status, 201)


class TestImporterSyncModes(object):

    def setup(self):
        # Since test config scenarios are complicated moved the setup inside the individual tests
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            self.vo_header = {'X-Rucio-VO': self.vo['vo']}
        else:
            self.vo = {}
            self.vo_header = {}

    def test_import_rses_append(self):
        """ IMPORTER (CORE): test import rse (APPEND mode). """
        # In rse sync mode append: New RSEs are created, existing RSEs are not modified, leftover RSEs are not deleted

        # RSE that did not exist before
        new_rse = rse_name_generator()

        # RSE missing from json
        old_rse = rse_name_generator()
        old_rse_id = add_rse(old_rse, **self.vo)

        # RSE that was disabled but is active on json
        disabled_rse = rse_name_generator()
        disabled_rse_id = add_rse(disabled_rse, **self.vo)
        del_rse(disabled_rse_id)

        data = {
            'rses': {
                new_rse: {
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
                disabled_rse: {
                    'rse_type': RSEType.TAPE,
                    'deterministic': True,
                    'volatile': True,
                    'region_code': 'DE',
                    'country_name': 'DE',
                    'staging_area': False,
                    'time_zone': 'Europe',
                    'longitude': 2,
                    'city': 'City',
                    'availability': 1,
                    'latitude': 1,
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
                    }, {
                        'scheme': 'scheme3',
                        'hostname': 'hostname3',
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
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='append', **self.vo)

        # Check RSE that did not exist before exists now
        check_rse(new_rse, data['rses'], **self.vo)

        # Check that old_rse was not disabled after import
        assert_equal(get_rse_id(old_rse, include_deleted=False, **self.vo), old_rse_id)

        # Check that disabled_rse dit not get enabled
        with assert_raises(RSENotFound):
            get_rse(rse_id=disabled_rse_id)

    def test_import_rses_edit(self):
        """ IMPORTER (CORE): test import rse (EDIT mode). """
        # In rse sync mode edit: New RSEs are created, existing RSEs are modified, leftover RSEs are not deleted

        # RSE that did not exist before
        new_rse = rse_name_generator()

        # RSE missing from json
        old_rse = rse_name_generator()
        old_rse_id = add_rse(old_rse, **self.vo)

        # RSE that was disabled but is active on json
        disabled_rse = rse_name_generator()
        disabled_rse_id = add_rse(disabled_rse, **self.vo)
        del_rse(disabled_rse_id)

        data = {
            'rses': {
                new_rse: {
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
                disabled_rse: {
                    'rse_type': RSEType.TAPE,
                    'deterministic': True,
                    'volatile': True,
                    'region_code': 'DE',
                    'country_name': 'DE',
                    'staging_area': False,
                    'time_zone': 'Europe',
                    'longitude': 2,
                    'city': 'City',
                    'availability': 1,
                    'latitude': 1,
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
                    }, {
                        'scheme': 'scheme3',
                        'hostname': 'hostname3',
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
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', **self.vo)

        # Check RSE that did not exist before exists now
        check_rse(new_rse, data['rses'], **self.vo)

        # Check that old_rse was not disabled after import
        assert_equal(get_rse_id(old_rse, include_deleted=False, **self.vo), old_rse_id)

        # Check that disabled_rse got enabled
        assert_equal(get_rse_id(disabled_rse, include_deleted=False, **self.vo), disabled_rse_id)

    def test_import_attributes_append(self):
        """ IMPORTER (CORE): test import attributes (APPEND mode). """
        # In attributes sync mode append: New attributes are created, existing attributes are not modified, leftover attributes are not deleted

        # RSE has less attributes than on json
        less_attr_rse = rse_name_generator()
        less_attr_rse_id = add_rse(less_attr_rse, **self.vo)
        add_rse_attribute(rse_id=less_attr_rse_id, key='attr1', value='test')

        # RSE has an attribute with different value
        diff_attr_rse = rse_name_generator()
        diff_attr_rse_id = add_rse(diff_attr_rse, **self.vo)
        add_rse_attribute(rse_id=diff_attr_rse_id, key='attr1', value='test_original')
        add_rse_attribute(rse_id=diff_attr_rse_id, key='attr2', value='test_original')

        # RSE has attributes that are missing from the json
        more_attr_rse = rse_name_generator()
        more_attr_rse_id = add_rse(more_attr_rse, **self.vo)
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr1', value='test_original')
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr2', value='test_original')
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr3', value='test_original')

        data = {
            'rses': {
                less_attr_rse: {
                    'attributes': {
                        'attr1': 'test',
                        'attr2': 'test_new'

                    }
                },
                diff_attr_rse: {
                    'attributes': {
                        'attr1': 'test_original_dif',
                        'attr2': 'test_different'
                    }
                },
                more_attr_rse: {
                    'attributes': {
                        'attr1': 'test_original',
                        'attr2': 'test_original'
                    }
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', attr_sync_method='append', **self.vo)

        # Check that attributes were added for less_attr_rse
        assert_equal(get_rse_attribute('attr2', rse_id=less_attr_rse_id, use_cache=False), ['test_new'])

        # Check that attributes were not modified for diff_attr_rse
        assert_equal(get_rse_attribute('attr2', rse_id=diff_attr_rse_id, use_cache=False), ['test_original'])

        # Check that attributes were missing from the json are not deleted
        assert_equal(get_rse_attribute('attr3', rse_id=more_attr_rse_id, use_cache=False), ['test_original'])

    def test_import_attributes_edit(self):
        """ IMPORTER (CORE): test import attributes (EDIT mode). """
        # In attributes sync mode edit: New attributes are created, existing attributes are modified, leftover attributes are not deleted

        # RSE has less attributes than on json
        less_attr_rse = rse_name_generator()
        less_attr_rse_id = add_rse(less_attr_rse, **self.vo)
        add_rse_attribute(rse_id=less_attr_rse_id, key='attr1', value='test')

        # RSE has an attribute with different value
        diff_attr_rse = rse_name_generator()
        diff_attr_rse_id = add_rse(diff_attr_rse, **self.vo)
        add_rse_attribute(rse_id=diff_attr_rse_id, key='attr1', value='test_original')
        add_rse_attribute(rse_id=diff_attr_rse_id, key='attr2', value='test_original')

        # RSE has attributes that are missing from the json
        more_attr_rse = rse_name_generator()
        more_attr_rse_id = add_rse(more_attr_rse, **self.vo)
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr1', value='test_original')
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr2', value='test_original')
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr3', value='test_original')

        data = {
            'rses': {
                less_attr_rse: {
                    'attributes': {
                        'attr1': 'test',
                        'attr2': 'test_new'

                    }
                },
                diff_attr_rse: {
                    'attributes': {
                        'attr1': 'test_original_dif',
                        'attr2': 'test_different'
                    }
                },
                more_attr_rse: {
                    'attributes': {
                        'attr1': 'test_original',
                        'attr2': 'test_original'
                    }
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', attr_sync_method='edit', **self.vo)

        # Check that attributes were added for less_attr_rse
        assert_equal(get_rse_attribute('attr2', rse_id=less_attr_rse_id, use_cache=False), ['test_new'])

        # Check that attributes were modified for diff_attr_rse
        assert_equal(get_rse_attribute('attr2', rse_id=diff_attr_rse_id, use_cache=False), ['test_different'])

        # Check that attributes that were missing from the json are not deleted
        assert_equal(get_rse_attribute('attr3', rse_id=more_attr_rse_id, use_cache=False), ['test_original'])

    def test_import_attributes_hard(self):
        """ IMPORTER (CORE): test import attributes (HARD mode). """
        # In attributes sync mode hard: New attributes are created, existing attributes are modified, leftover attributes are deleted

        # RSE has less attributes than on json
        less_attr_rse = rse_name_generator()
        less_attr_rse_id = add_rse(less_attr_rse, **self.vo)
        add_rse_attribute(rse_id=less_attr_rse_id, key='attr1', value='test')

        # RSE has an attribute with different value
        diff_attr_rse = rse_name_generator()
        diff_attr_rse_id = add_rse(diff_attr_rse, **self.vo)
        add_rse_attribute(rse_id=diff_attr_rse_id, key='attr1', value='test_original')
        add_rse_attribute(rse_id=diff_attr_rse_id, key='attr2', value='test_original')

        # RSE has attributes that are missing from the json
        more_attr_rse = rse_name_generator()
        more_attr_rse_id = add_rse(more_attr_rse, **self.vo)
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr1', value='test_original')
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr2', value='test_original')
        add_rse_attribute(rse_id=more_attr_rse_id, key='attr3', value='test_original')

        data = {
            'rses': {
                less_attr_rse: {
                    'attributes': {
                        'attr1': 'test',
                        'attr2': 'test_new'

                    }
                },
                diff_attr_rse: {
                    'attributes': {
                        'attr1': 'test_original_dif',
                        'attr2': 'test_different'
                    }
                },
                more_attr_rse: {
                    'attributes': {
                        'attr1': 'test_original',
                        'attr2': 'test_original'
                    }
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', attr_sync_method='hard', **self.vo)

        # Check that attributes were added for less_attr_rse
        assert_equal(get_rse_attribute('attr2', rse_id=less_attr_rse_id, use_cache=False), ['test_new'])

        # Check that attributes were modified for diff_attr_rse
        assert_equal(get_rse_attribute('attr2', rse_id=diff_attr_rse_id, use_cache=False), ['test_different'])

        # Check that attributes that were missing from the json are deleted
        assert_equal(get_rse_attribute('attr3', rse_id=more_attr_rse_id, use_cache=False), [])

    def test_import_protocols_append(self):
        """ IMPORTER (CORE): test import protocols (APPEND mode). """
        # In protocols sync mode append: New protocols are created, existing protocols are not modified, leftover protocols are not deleted

        less_prot_rse = rse_name_generator()
        less_prot_rse_id = add_rse(less_prot_rse, **self.vo)
        add_protocol(less_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})

        diff_prot_rse = rse_name_generator()
        diff_prot_rse_id = add_rse(diff_prot_rse, **self.vo)
        add_protocol(diff_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})

        more_prot_rse = rse_name_generator()
        more_prot_rse_id = add_rse(more_prot_rse, **self.vo)
        add_protocol(more_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})
        add_protocol(more_prot_rse_id, {'scheme': 'scheme2', 'hostname': 'hostname2', 'port': 1000, 'impl': 'TODO'})
        add_protocol(more_prot_rse_id, {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'})

        data = {
            'rses': {
                less_prot_rse: {
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
                    'protocols': [
                        {
                            'scheme': 'scheme',
                            'hostname': 'hostname',
                            'port': 1000,
                            'impl': 'impl'
                        },
                        {
                            'scheme': 'scheme2',
                            'hostname': 'hostname2',
                            'port': 1000,
                            'impl': 'impl'
                        }
                    ]
                },
                diff_prot_rse: {
                    'rse_type': RSEType.DISK,
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
                        'impl': 'impl_new'
                    }]
                },
                more_prot_rse: {
                    'rse_type': RSEType.DISK,
                    'availability': 2,
                    'city': 'NewCity',
                    'region_code': 'CH',
                    'country_name': 'switzerland',
                    'staging_area': False,
                    'time_zone': 'Europe',
                    'latitude': 1,
                    'longitude': 2,
                    'deterministic': True,
                    'volatile': False,
                    'protocols': [
                        {
                            'scheme': 'scheme',
                            'hostname': 'hostname',
                            'port': 1000,
                            'impl': 'impl'
                        },
                        {
                            'scheme': 'scheme2',
                            'hostname': 'hostname2',
                            'port': 1000,
                            'impl': 'impl'
                        }
                    ]
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', protocol_sync_method='append', **self.vo)

        # Check that new protocol was added
        protocols = get_rse_protocols(less_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in protocols['protocols']]
        dp = data['rses'][less_prot_rse]['protocols'][0]
        data_protocol_formated = {'hostname': dp['hostname'], 'scheme': dp['scheme'], 'port': dp['port'], 'impl': dp.get('impl', ''), 'prefix': dp.get('prefix', '')}
        assert_in(data_protocol_formated, protocols_formated)

        # Check that protocol was not modified
        protocols = get_rse_protocols(diff_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'}
        assert_in(data_protocol_formated, protocols_formated)

        # Check that missing protocol was not deleted
        protocols = get_rse_protocols(more_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'}
        assert_in(data_protocol_formated, protocols_formated)

    def test_import_protocols_edit(self):
        """ IMPORTER (CORE): test import protocols (EDIT mode). """
        # In protocols sync mode edit: New protocols are created, existing protocols are modified, leftover protocols are not deleted

        less_prot_rse = rse_name_generator()
        less_prot_rse_id = add_rse(less_prot_rse, **self.vo)
        add_protocol(less_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})

        diff_prot_rse = rse_name_generator()
        diff_prot_rse_id = add_rse(diff_prot_rse, **self.vo)
        add_protocol(diff_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})

        more_prot_rse = rse_name_generator()
        more_prot_rse_id = add_rse(more_prot_rse, **self.vo)
        add_protocol(more_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})
        add_protocol(more_prot_rse_id, {'scheme': 'scheme2', 'hostname': 'hostname2', 'port': 1000, 'impl': 'TODO'})
        add_protocol(more_prot_rse_id, {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'})

        data = {
            'rses': {
                less_prot_rse: {
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
                    'protocols': [
                        {
                            'scheme': 'scheme',
                            'hostname': 'hostname',
                            'port': 1000,
                            'impl': 'impl'
                        },
                        {
                            'scheme': 'scheme2',
                            'hostname': 'hostname2',
                            'port': 1000,
                            'impl': 'impl'
                        }
                    ]
                },
                diff_prot_rse: {
                    'rse_type': RSEType.DISK,
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
                        'scheme': 'scheme1',
                        'hostname': 'hostname1',
                        'port': 1000,
                        'impl': 'impl_new'
                    }]
                },
                more_prot_rse: {
                    'rse_type': RSEType.DISK,
                    'availability': 2,
                    'city': 'NewCity',
                    'region_code': 'CH',
                    'country_name': 'switzerland',
                    'staging_area': False,
                    'time_zone': 'Europe',
                    'latitude': 1,
                    'longitude': 2,
                    'deterministic': True,
                    'volatile': False,
                    'protocols': [
                        {
                            'scheme': 'scheme',
                            'hostname': 'hostname',
                            'port': 1000,
                            'impl': 'impl'
                        },
                        {
                            'scheme': 'scheme2',
                            'hostname': 'hostname2',
                            'port': 1000,
                            'impl': 'impl'
                        }
                    ]
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', protocol_sync_method='edit', **self.vo)

        # Check that new protocol was added
        protocols = get_rse_protocols(less_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in protocols['protocols']]
        dp = data['rses'][less_prot_rse]['protocols'][0]
        data_protocol_formated = {'hostname': dp['hostname'], 'scheme': dp['scheme'], 'port': dp['port'], 'impl': dp.get('impl', ''), 'prefix': dp.get('prefix', '')}
        assert_in(data_protocol_formated, protocols_formated)

        # Check that protocol was added
        protocols = get_rse_protocols(diff_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'impl_new'}
        assert_in(data_protocol_formated, protocols_formated)

        # Check that missing protocol was not deleted
        protocols = get_rse_protocols(more_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'}
        assert_in(data_protocol_formated, protocols_formated)

    def test_import_protocols_hard(self):
        """ IMPORTER (CORE): test import protocols (HARD mode). """
        # In protocols sync mode hard: New protocols are created, existing protocols are modified, leftover protocols are deleted

        less_prot_rse = rse_name_generator()
        less_prot_rse_id = add_rse(less_prot_rse, **self.vo)
        add_protocol(less_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})

        diff_prot_rse = rse_name_generator()
        diff_prot_rse_id = add_rse(diff_prot_rse, **self.vo)
        add_protocol(diff_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})

        more_prot_rse = rse_name_generator()
        more_prot_rse_id = add_rse(more_prot_rse, **self.vo)
        add_protocol(more_prot_rse_id, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})
        add_protocol(more_prot_rse_id, {'scheme': 'scheme2', 'hostname': 'hostname2', 'port': 1000, 'impl': 'TODO'})
        add_protocol(more_prot_rse_id, {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'})

        data = {
            'rses': {
                less_prot_rse: {
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
                    'protocols': [
                        {
                            'scheme': 'scheme',
                            'hostname': 'hostname',
                            'port': 1000,
                            'impl': 'impl'
                        },
                        {
                            'scheme': 'scheme2',
                            'hostname': 'hostname2',
                            'port': 1000,
                            'impl': 'impl'
                        }
                    ]
                },
                diff_prot_rse: {
                    'rse_type': RSEType.DISK,
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
                        'scheme': 'scheme1',
                        'hostname': 'hostname1',
                        'port': 1000,
                        'impl': 'impl_new'
                    }]
                },
                more_prot_rse: {
                    'rse_type': RSEType.DISK,
                    'availability': 2,
                    'city': 'NewCity',
                    'region_code': 'CH',
                    'country_name': 'switzerland',
                    'staging_area': False,
                    'time_zone': 'Europe',
                    'latitude': 1,
                    'longitude': 2,
                    'deterministic': True,
                    'volatile': False,
                    'protocols': [
                        {
                            'scheme': 'scheme',
                            'hostname': 'hostname',
                            'port': 1000,
                            'impl': 'impl'
                        },
                        {
                            'scheme': 'scheme2',
                            'hostname': 'hostname2',
                            'port': 1000,
                            'impl': 'impl'
                        }
                    ]
                }
            }
        }

        import_rses(rses=deepcopy(data['rses']), rse_sync_method='edit', protocol_sync_method='hard', **self.vo)

        # Check that new protocol was added
        protocols = get_rse_protocols(less_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in protocols['protocols']]
        dp = data['rses'][less_prot_rse]['protocols'][0]
        data_protocol_formated = {'hostname': dp['hostname'], 'scheme': dp['scheme'], 'port': dp['port'], 'impl': dp.get('impl', ''), 'prefix': dp.get('prefix', '')}
        assert_in(data_protocol_formated, protocols_formated)

        # Check that protocol was modified
        protocols = get_rse_protocols(diff_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'impl_new'}
        assert_in(data_protocol_formated, protocols_formated)

        # Check that missing protocol was deleted
        protocols = get_rse_protocols(more_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'}
        assert(data_protocol_formated not in protocols_formated)


class TestExporter(object):
    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            self.vo_header = {'X-Rucio-VO': self.vo['vo']}
        else:
            self.vo = {}
            self.vo_header = {}

        self.db_session = session.get_session()
        self.db_session.query(models.Distance).delete()
        self.db_session.commit()
        self.rse_1 = 'MOCK'
        self.rse_1_id = get_rse_id(self.rse_1, **self.vo)
        self.rse_2 = 'MOCK2'
        self.rse_2_id = get_rse_id(self.rse_2, **self.vo)
        ranking = 10
        add_distance(self.rse_1_id, self.rse_2_id, ranking)
        self.distances = {
            self.rse_1: {
                self.rse_2: get_distances(self.rse_1_id, self.rse_2_id)[0]
            }
        }
        self.distances_core = {
            self.rse_1_id: {
                self.rse_2_id: get_distances(self.rse_1_id, self.rse_2_id)[0]
            }
        }

    def test_export_core(self):
        """ EXPORT (CORE): Test the export of data."""
        data = export_data(**self.vo)
        assert_equal(data['rses'], export_rses(**self.vo))
        assert_equal(data['distances'], self.distances_core)

    def test_export_client(self):
        """ EXPORT (CLIENT): Test the export of data."""
        export_client = ExportClient()
        data = export_client.export_data()
        rses = {}
        for rse in list_rses(filters=self.vo):
            rse_name = rse['rse']
            rse_id = rse['id']
            rses[rse_name] = export_rse(rse_id=rse_id)
        assert_equal(data['rses'], parse_response(render_json(**rses)))
        assert_equal(data['distances'], parse_response(render_json(**self.distances)))

    def test_export_rest(self):
        """ EXPORT (REST): Test the export of data."""
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        r2 = TestApp(export_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        rses = export_rses(**self.vo)
        sanitised = {}
        for rse_id in rses:
            sanitised[get_rse_name(rse_id=rse_id)] = rses[rse_id]
        rses = sanitised

        assert_equal(r2.status, 200)
        assert_equal(parse_response(r2.body), parse_response(render_json(**{'rses': rses, 'distances': self.distances})))


class TestExportImport(object):
    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            self.vo_header = {'X-Rucio-VO': self.vo['vo']}
        else:
            self.vo = {}
            self.vo_header = {}

    def tearDown(self):
        reset_rses()

    def test_export_import(self):
        """ IMPORT/EXPORT (REST): Test the export and import of data together to check same syntax."""
        if not config_has_section('importer'):
            config_add_section('importer')
            config_set('importer', 'rse_sync_method', 'hard')
            config_set('importer', 'attr_method', 'hard')
            config_set('importer', 'protocol_method', 'hard')

        # Setup new RSE, distance, attribute, limits
        new_rse = rse_name_generator()
        add_rse(new_rse, **self.vo)

        # Get token
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}

        # Export data
        r2 = TestApp(export_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        exported_data = parse_response(r2.body)

        # Import data
        r3 = TestApp(import_app.wsgifunc(*mw)).post('/', headers=headers2, expect_errors=True, params=render_json(**exported_data))
        assert_equal(r3.status, 201)
