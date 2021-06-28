# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

from __future__ import print_function

import unittest
from copy import deepcopy

import pytest

from rucio.client.exportclient import ExportClient
from rucio.client.importclient import ImportClient
from rucio.common.config import config_set, config_add_section, config_has_section, config_get_bool
from rucio.common.exception import RSENotFound
from rucio.common.types import InternalAccount
from rucio.common.utils import render_json, parse_response
from rucio.core.account import add_account, get_account
from rucio.core.distance import add_distance, get_distances
from rucio.core.exporter import export_data, export_rses
from rucio.core.identity import add_identity, list_identities, add_account_identity, list_accounts_for_identity
from rucio.core.importer import import_data, import_rses
from rucio.core.rse import get_rse_id, get_rse_name, add_rse, get_rse, add_protocol, get_rse_protocols, \
    list_rse_attributes, get_rse_limits, set_rse_limits, add_rse_attribute, list_rses, export_rse, get_rse_attribute, \
    del_rse
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import RSEType, AccountType, IdentityType, AccountStatus
from rucio.tests.common import rse_name_generator, headers, auth, hdrdict
from rucio.tests.common_server import get_vo


def check_rse(rse_name, test_data, vo='def'):
    rse_id = get_rse_id(rse=rse_name, vo=vo)
    rse = get_rse(rse_id=rse_id)
    assert rse['rse'] == rse_name
    assert rse['vo'] == vo
    assert rse['rse_type'] == test_data[rse_name]['rse_type']
    assert rse['region_code'] == test_data[rse_name]['region_code']
    assert rse['country_name'] == test_data[rse_name]['country_name']
    assert rse['time_zone'] == test_data[rse_name]['time_zone']
    assert rse['volatile'] == test_data[rse_name]['volatile']
    assert rse['deterministic'] == test_data[rse_name]['deterministic']
    assert rse['city'] == test_data[rse_name]['city']
    assert rse['staging_area'] == test_data[rse_name]['staging_area']
    assert rse['longitude'] == test_data[rse_name]['longitude']
    assert rse['latitude'] == test_data[rse_name]['latitude']
    assert rse['availability'] == test_data[rse_name]['availability']


def check_protocols(rse, test_data, vo='def'):
    rse_id = get_rse_id(rse=rse, vo=vo)
    protocols = get_rse_protocols(rse_id)
    assert test_data[rse]['lfn2pfn_algorithm'] == get_rse_attribute('lfn2pfn_algorithm', rse_id=rse_id, use_cache=False)[0]
    assert test_data[rse]['verify_checksum'] == get_rse_attribute('verify_checksum', rse_id=rse_id, use_cache=False)[0]
    assert test_data[rse]['availability_write'] == protocols['availability_write']
    assert test_data[rse]['availability_read'] == protocols['availability_read']
    assert test_data[rse]['availability_delete'] == protocols['availability_delete']
    protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl'], 'prefix': protocol['prefix']} for protocol in protocols['protocols']]
    for protocol in test_data[rse]['protocols']:
        assert {'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol.get('impl', ''), 'prefix': protocol.get('prefix', '')} in protocols


@pytest.fixture
def reset_rses():
    yield
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


@pytest.fixture
def importer_example_data(vo):
    if not config_has_section('importer'):
        config_add_section('importer')
    config_set('importer', 'rse_sync_method', 'hard')
    config_set('importer', 'attr_method', 'edit')
    config_set('importer', 'protocol_method', 'edit')

    class ImporterExampleData:
        new_rse = None
        old_rse_1 = None
        old_rse_id_1 = None
        old_rse_2 = None
        old_rse_id_2 = None
        old_rse_3 = None
        old_rse_id_3 = None
        old_rse_4 = None
        old_rse_id_4 = None
        old_account_1 = None
        old_account_2 = None
        identity_to_be_removed = None
        identity_to_be_added_to_account = None
        data1 = None
        data2 = None
        data3 = None

        def check_accounts(self):
            db_identities = list_identities()
            for account in self.data1['accounts']:
                # check existence
                db_account = get_account(account=account['account'])
                assert db_account['account'] == account['account']

                # check properties
                email = account.get('email')
                if email:
                    assert db_account['email'] == account['email']

                # check identities
                identities = account.get('identities')
                if identities:
                    for identity in identities:
                        # check identity creation and identity-account association
                        identity_type = IdentityType[identity['type'].upper()]
                        identity = identity['identity']
                        assert (identity, identity_type) in db_identities
                        accounts_for_identity = list_accounts_for_identity(identity, identity_type)
                        assert account['account'] in accounts_for_identity

            # check removal of account
            account = get_account(self.old_account_1)
            assert account['status'] == AccountStatus.DELETED

            # check removal of identities
            accounts_for_identity = list_accounts_for_identity(self.identity_to_be_removed, IdentityType.X509)
            assert account['account'] not in accounts_for_identity

    example_data = ImporterExampleData()

    # New RSE
    example_data.new_rse = rse_name_generator()

    # RSE 1 that already exists
    example_data.old_rse_1 = rse_name_generator()
    example_data.old_rse_id_1 = add_rse(example_data.old_rse_1, availability=1, region_code='DE', country_name='DE', deterministic=True, volatile=True, staging_area=True, time_zone='Europe', latitude='1', longitude='2', vo=vo)
    add_protocol(example_data.old_rse_id_1, {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'})
    add_protocol(example_data.old_rse_id_1, {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'})

    set_rse_limits(rse_id=example_data.old_rse_id_1, name='MaxBeingDeletedFiles', value='10')
    set_rse_limits(rse_id=example_data.old_rse_id_1, name='MinFreeSpace', value='10')
    add_rse_attribute(rse_id=example_data.old_rse_id_1, key='attr1', value='test10')
    add_rse_attribute(rse_id=example_data.old_rse_id_1, key='lfn2pfn_algorithm', value='test10')
    add_rse_attribute(rse_id=example_data.old_rse_id_1, key='verify_checksum', value=True)

    # RSE 2 that already exists
    example_data.old_rse_2 = rse_name_generator()
    example_data.old_rse_id_2 = add_rse(example_data.old_rse_2, vo=vo)

    # RSE 3 that already exists
    example_data.old_rse_3 = rse_name_generator()
    example_data.old_rse_id_3 = add_rse(example_data.old_rse_3, vo=vo)

    # RSE 4 that already exists
    example_data.old_rse_4 = rse_name_generator()
    example_data.old_rse_id_4 = add_rse(example_data.old_rse_4, vo=vo)

    # Distance that already exists
    add_distance(example_data.old_rse_id_1, example_data.old_rse_id_2)

    # Account 1 that already exists
    example_data.old_account_1 = InternalAccount(rse_name_generator(), vo=vo)
    add_account(example_data.old_account_1, AccountType.USER, email='test')

    # Account 2 that already exists
    example_data.old_account_2 = InternalAccount(rse_name_generator(), vo=vo)
    add_account(example_data.old_account_2, AccountType.USER, email='test')

    # Identity that should be removed
    example_data.identity_to_be_removed = rse_name_generator()
    add_identity(example_data.identity_to_be_removed, IdentityType.X509, email='email')
    add_account_identity(example_data.identity_to_be_removed, IdentityType.X509, example_data.old_account_2, 'email')

    # Identity that already exsits but should be added to the account
    example_data.identity_to_be_added_to_account = rse_name_generator()
    add_identity(example_data.identity_to_be_added_to_account, IdentityType.X509, email='email')

    example_data.data1 = {
        'rses': {
            example_data.new_rse: {
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
            example_data.old_rse_1: {
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
            example_data.old_rse_2: {},
            example_data.old_rse_3: {}
        },
        'distances': {
            example_data.old_rse_1: {
                example_data.old_rse_2: {'src_rse': example_data.old_rse_1, 'dest_rse': example_data.old_rse_2, 'ranking': 10},
                example_data.old_rse_3: {'src_rse': example_data.old_rse_1, 'dest_rse': example_data.old_rse_3, 'ranking': 4}
            }
        },
        'accounts': [{
            'account': InternalAccount('new_account', vo=vo),
            'email': 'email',
            'identities': [{
                'type': 'userpass',
                'identity': 'username',
                'password': 'password'
            }]
        }, {
            'account': InternalAccount('new_account2', vo=vo),
            'email': 'email'
        }, {
            'account': example_data.old_account_2,
            'email': 'new_email',
            'identities': [
                {
                    'identity': example_data.identity_to_be_added_to_account,
                    'type': 'x509'
                },
                {
                    'type': 'userpass',
                    'identity': 'username2',
                    'password': 'password'
                }
            ]
        }, {
            'account': InternalAccount('jdoe', vo=vo),
            'email': 'email'
        }]
    }

    example_data.data2 = {'rses': {example_data.new_rse: {'rse': example_data.new_rse}}}
    example_data.data3 = {'distances': {}}
    return example_data


@pytest.mark.noparallel(reason='resets pre-defined RSE, changes global configuration value')
def test_importer_core(vo, importer_example_data, reset_rses):
    """ IMPORTER (CORE): test import. """
    import_data(data=deepcopy(importer_example_data.data1), vo=vo)

    # RSE that had not existed before
    check_rse(importer_example_data.new_rse, importer_example_data.data1['rses'], vo=vo)
    check_protocols(importer_example_data.new_rse, importer_example_data.data1['rses'], vo=vo)

    new_rse_id = get_rse_id(rse=importer_example_data.new_rse, vo=vo)

    attributes = list_rse_attributes(rse_id=new_rse_id)
    assert attributes['attr1'] == 'test'
    limits = get_rse_limits(rse_id=new_rse_id)
    assert limits['MinFreeSpace'] == 20000

    # RSE 1 that already exists
    check_rse(importer_example_data.old_rse_1, importer_example_data.data1['rses'], vo=vo)

    # one protocol should be created, one should be updated
    check_protocols(importer_example_data.old_rse_1, importer_example_data.data1['rses'], vo=vo)

    # one protocol should be removed as it is not specified in the import data
    protocols = get_rse_protocols(importer_example_data.old_rse_id_1)
    protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
    assert {'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols

    attributes = list_rse_attributes(rse_id=importer_example_data.old_rse_id_1)
    assert attributes['attr1'] == 'test1'
    assert attributes['attr2'] == 'test2'

    limits = get_rse_limits(rse_id=importer_example_data.old_rse_id_1)
    assert limits['MaxBeingDeletedFiles'] == 1000
    assert limits['MinFreeSpace'] == 10000

    distance = get_distances(importer_example_data.old_rse_id_1, importer_example_data.old_rse_id_2)[0]
    assert distance['ranking'] == 10

    distance = get_distances(importer_example_data.old_rse_id_1, importer_example_data.old_rse_id_3)[0]
    assert distance['ranking'] == 4

    importer_example_data.check_accounts()

    # RSE 4 should be flagged as deleted as it is missing in the import data
    with pytest.raises(RSENotFound):
        get_rse(rse_id=importer_example_data.old_rse_id_4)

    import_data(data=importer_example_data.data2, vo=vo)
    import_data(data=importer_example_data.data3, vo=vo)


@pytest.mark.noparallel(reason='resets pre-defined RSE, changes global configuration value')
def test_importer_client(vo, importer_example_data, reset_rses):
    """ IMPORTER (CLIENT): test import. """
    import_client = ImportClient()
    import_client.import_data(data=deepcopy(importer_example_data.data1))

    # RSE that had not existed before
    check_rse(importer_example_data.new_rse, importer_example_data.data1['rses'], vo=vo)
    check_protocols(importer_example_data.new_rse, importer_example_data.data1['rses'], vo=vo)

    new_rse_id = get_rse_id(rse=importer_example_data.new_rse, vo=vo)

    protocols = get_rse_protocols(importer_example_data.old_rse_id_1)
    protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
    assert {'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols

    attributes = list_rse_attributes(rse_id=new_rse_id)
    assert attributes['attr1'] == 'test'

    limits = get_rse_limits(rse_id=new_rse_id)
    assert limits['MinFreeSpace'] == 20000

    # RSE 1 that already exists
    check_rse(importer_example_data.old_rse_1, importer_example_data.data1['rses'], vo=vo)
    check_protocols(importer_example_data.old_rse_1, importer_example_data.data1['rses'], vo=vo)

    attributes = list_rse_attributes(rse_id=importer_example_data.old_rse_id_1)
    assert attributes['attr1'] == 'test1'
    assert attributes['attr2'] == 'test2'

    limits = get_rse_limits(rse_id=importer_example_data.old_rse_id_1)
    assert limits['MaxBeingDeletedFiles'] == 1000
    assert limits['MinFreeSpace'] == 10000

    distance = get_distances(importer_example_data.old_rse_id_1, importer_example_data.old_rse_id_2)[0]
    assert distance['ranking'] == 10

    distance = get_distances(importer_example_data.old_rse_id_1, importer_example_data.old_rse_id_3)[0]
    assert distance['ranking'] == 4

    importer_example_data.check_accounts()

    # If the default sync method is not 'hard', RSE old_rse_id_4 should still be there
    # with pytest.raises(RSENotFound):
    #     get_rse(rse_id=importer_example_data.old_rse_id_4)

    import_client.import_data(data=importer_example_data.data2)
    import_client.import_data(data=importer_example_data.data3)


@pytest.mark.noparallel(reason='resets pre-defined RSE, changes global configuration value')
def test_importer_rest(vo, rest_client, auth_token, importer_example_data, reset_rses):
    """ IMPORTER (REST): test import. """
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
    response = rest_client.post('/import/', headers=headers(auth(auth_token), hdrdict(headers_dict)), data=render_json(**importer_example_data.data1))
    assert response.status_code == 201

    # RSE that not existed before
    check_rse(importer_example_data.new_rse, importer_example_data.data1['rses'], vo=vo)
    check_protocols(importer_example_data.new_rse, importer_example_data.data1['rses'], vo=vo)

    new_rse_id = get_rse_id(rse=importer_example_data.new_rse, vo=vo)

    protocols = get_rse_protocols(importer_example_data.old_rse_id_1)
    protocols = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port']} for protocol in protocols['protocols']]
    assert {'hostename': 'hostname3', 'port': 1000, 'scheme': 'scheme3'} not in protocols

    attributes = list_rse_attributes(rse_id=new_rse_id)
    assert attributes['attr1'] == 'test'

    limits = get_rse_limits(rse_id=new_rse_id)
    assert limits['MinFreeSpace'] == 20000

    # RSE 1 that already existed before
    check_rse(importer_example_data.old_rse_1, importer_example_data.data1['rses'], vo=vo)
    check_protocols(importer_example_data.old_rse_1, importer_example_data.data1['rses'], vo=vo)

    attributes = list_rse_attributes(rse_id=importer_example_data.old_rse_id_1)
    assert attributes['attr1'] == 'test1'
    assert attributes['attr2'] == 'test2'

    limits = get_rse_limits(rse_id=importer_example_data.old_rse_id_1)
    assert limits['MaxBeingDeletedFiles'] == 1000
    assert limits['MinFreeSpace'] == 10000

    distance = get_distances(importer_example_data.old_rse_id_1, importer_example_data.old_rse_id_2)[0]
    assert distance['ranking'] == 10

    distance = get_distances(importer_example_data.old_rse_id_1, importer_example_data.old_rse_id_3)[0]
    assert distance['ranking'] == 4

    importer_example_data.check_accounts()

    with pytest.raises(RSENotFound):
        get_rse(rse_id=importer_example_data.old_rse_id_4)

    response = rest_client.post('/import/', headers=headers(auth(auth_token), hdrdict(headers_dict)), data=render_json(**importer_example_data.data2))
    assert response.status_code == 201

    response = rest_client.post('/import/', headers=headers(auth(auth_token), hdrdict(headers_dict)), data=render_json(**importer_example_data.data3))
    assert response.status_code == 201


@pytest.mark.noparallel(reason='fails when run in parallel')
class TestImporterSyncModes(unittest.TestCase):

    def setUp(self):
        # Since test config scenarios are complicated moved the setup inside the individual tests
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

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
        assert get_rse_id(old_rse, include_deleted=False, **self.vo) == old_rse_id

        # Check that disabled_rse dit not get enabled
        with pytest.raises(RSENotFound):
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
        assert get_rse_id(old_rse, include_deleted=False, **self.vo) == old_rse_id

        # Check that disabled_rse got enabled
        assert get_rse_id(disabled_rse, include_deleted=False, **self.vo) == disabled_rse_id

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
        assert get_rse_attribute('attr2', rse_id=less_attr_rse_id, use_cache=False) == ['test_new']

        # Check that attributes were not modified for diff_attr_rse
        assert get_rse_attribute('attr2', rse_id=diff_attr_rse_id, use_cache=False) == ['test_original']

        # Check that attributes were missing from the json are not deleted
        assert get_rse_attribute('attr3', rse_id=more_attr_rse_id, use_cache=False) == ['test_original']

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
        assert get_rse_attribute('attr2', rse_id=less_attr_rse_id, use_cache=False) == ['test_new']

        # Check that attributes were modified for diff_attr_rse
        assert get_rse_attribute('attr2', rse_id=diff_attr_rse_id, use_cache=False) == ['test_different']

        # Check that attributes that were missing from the json are not deleted
        assert get_rse_attribute('attr3', rse_id=more_attr_rse_id, use_cache=False) == ['test_original']

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
        assert get_rse_attribute('attr2', rse_id=less_attr_rse_id, use_cache=False) == ['test_new']

        # Check that attributes were modified for diff_attr_rse
        assert get_rse_attribute('attr2', rse_id=diff_attr_rse_id, use_cache=False) == ['test_different']

        # Check that attributes that were missing from the json are deleted
        assert get_rse_attribute('attr3', rse_id=more_attr_rse_id, use_cache=False) == []

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
        assert data_protocol_formated in protocols_formated

        # Check that protocol was not modified
        protocols = get_rse_protocols(diff_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'TODO'}
        assert data_protocol_formated in protocols_formated

        # Check that missing protocol was not deleted
        protocols = get_rse_protocols(more_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'}
        assert data_protocol_formated in protocols_formated

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
        assert data_protocol_formated in protocols_formated

        # Check that protocol was added
        protocols = get_rse_protocols(diff_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'impl_new'}
        assert data_protocol_formated in protocols_formated

        # Check that missing protocol was not deleted
        protocols = get_rse_protocols(more_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'}
        assert data_protocol_formated in protocols_formated

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
        assert data_protocol_formated in protocols_formated

        # Check that protocol was modified
        protocols = get_rse_protocols(diff_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme1', 'hostname': 'hostname1', 'port': 1000, 'impl': 'impl_new'}
        assert data_protocol_formated in protocols_formated

        # Check that missing protocol was deleted
        protocols = get_rse_protocols(more_prot_rse_id)
        protocols_formated = [{'hostname': protocol['hostname'], 'scheme': protocol['scheme'], 'port': protocol['port'], 'impl': protocol['impl']} for protocol in protocols['protocols']]
        data_protocol_formated = {'scheme': 'scheme3', 'hostname': 'hostname3', 'port': 1000, 'impl': 'TODO'}
        assert(data_protocol_formated not in protocols_formated)


@pytest.fixture
def distances_data(vo):
    db_session = session.get_session()
    db_session.query(models.Distance).delete()
    db_session.commit()

    rse_1 = 'MOCK'
    rse_1_id = get_rse_id(rse_1, vo=vo)
    rse_2 = 'MOCK2'
    rse_2_id = get_rse_id(rse_2, vo=vo)
    ranking = 10
    add_distance(rse_1_id, rse_2_id, ranking)
    distances = get_distances(rse_1_id, rse_2_id)[0]

    return {'distances': distances, 'rse_1': rse_1, 'rse_1_id': rse_1_id, 'rse_2': rse_2, 'rse_2_id': rse_2_id}


@pytest.mark.noparallel(reason='modifies distance on pre-defined RSE')
def test_export_core(vo, distances_data):
    """ EXPORT (CORE): Test the export of data."""
    data = export_data(vo=vo)
    assert data['rses'] == export_rses(vo=vo)
    distances_cmp = {
        distances_data['rse_1_id']: {
            distances_data['rse_2_id']: distances_data['distances']
        }
    }
    assert distances_cmp == data['distances']


@pytest.mark.noparallel(reason='modifies distance on pre-defined RSE')
def test_export_client(vo, distances_data):
    """ EXPORT (CLIENT): Test the export of data."""
    export_client = ExportClient()
    data = export_client.export_data()
    rses = {}
    for rse in list_rses(filters={'vo': vo}):
        rse_name = rse['rse']
        rse_id = rse['id']
        rses[rse_name] = export_rse(rse_id=rse_id)
    assert data['rses'] == parse_response(render_json(**rses))
    distances_cmp = {
        distances_data['rse_1']: {
            distances_data['rse_2']: distances_data['distances']
        }
    }
    assert parse_response(render_json(**distances_cmp)) == data['distances']
    data = export_client.export_data(distance=False)
    assert 'distances' not in data


@pytest.mark.noparallel(reason='modifies distance on pre-defined RSE')
def test_export_rest(vo, rest_client, auth_token, distances_data):
    """ EXPORT (REST): Test the export of data."""
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}

    rses = export_rses(vo=vo)
    sanitised = {}
    for rse_id in rses:
        sanitised[get_rse_name(rse_id=rse_id)] = rses[rse_id]
    rses = sanitised

    response = rest_client.get('/export/', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 200
    distances_cmp = {
        distances_data['rse_1']: {
            distances_data['rse_2']: distances_data['distances']
        }
    }
    assert parse_response(render_json(**{'rses': rses, 'distances': distances_cmp})) == parse_response(response.get_data(as_text=True))


@pytest.mark.noparallel(reason='resets pre-defined RSE, changes global configuration value')
def test_export_import(vo, rest_client, auth_token, reset_rses):
    """ IMPORT/EXPORT (REST): Test the export and import of data together to check same syntax."""
    if not config_has_section('importer'):
        config_add_section('importer')
        config_set('importer', 'rse_sync_method', 'hard')
        config_set('importer', 'attr_method', 'hard')
        config_set('importer', 'protocol_method', 'hard')

    new_rse = rse_name_generator()
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}

    # Setup new RSE, distance, attribute, limits
    add_rse(new_rse, vo=vo)

    # Export data
    response = rest_client.get('/export/', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 200
    exported_data = parse_response(response.get_data(as_text=True))

    # Import data
    response = rest_client.post('/import/', headers=headers(auth(auth_token), hdrdict(headers_dict)), data=render_json(**exported_data))
    assert response.status_code == 201
