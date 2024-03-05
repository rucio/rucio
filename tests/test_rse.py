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

import pytest

from rucio.client.replicaclient import ReplicaClient
from rucio.common import exception
from rucio.common.exception import (Duplicate, RSENotFound, RSEProtocolNotSupported,
                                    InvalidObject, ResourceTemporaryUnavailable,
                                    RSEAttributeNotFound, RSEOperationNotSupported,
                                    InputValidationError)
from rucio.common.schema import get_schema_value
from rucio.common.utils import GLOBALLY_SUPPORTED_CHECKSUMS, CHECKSUM_KEY
from rucio.core.account_limit import set_local_account_limit, get_rse_account_usage
from rucio.core.did import add_did, attach_dids
from rucio.core.rule import add_rule
from rucio.core.request import set_transfer_limit, delete_transfer_limit
from rucio.core.rse import (add_rse, get_rse_id, del_rse, restore_rse, list_rses,
                            rse_exists, add_rse_attribute, list_rse_attributes,
                            get_rse_transfer_limits,
                            get_rse_protocols,
                            del_rse_attribute, get_rse_attribute, get_rse, rse_is_empty,
                            parse_checksum_support_attribute,
                            get_rse_supported_checksums_from_attributes,
                            update_rse)
from rucio.daemons.abacus.account import account_update
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import RSEType, DIDType
from rucio.rse import rsemanager as mgr
from rucio.tests.common import rse_name_generator, hdrdict, auth, headers, did_name_generator
from .test_rule import create_files


class TestRSECoreApi:

    def test_create_and_check_for_rse(self, vo):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE """
        rse_name = rse_name_generator()
        invalid_rse = 'BLAHBLAH'
        properties = {
            'ASN': 'ASN',
            'availability_read': False,
            'availability_write': True,
            'availability_delete': False,
            'deterministic': True,
            'volatile': True,
            'city': 'city',
            'region_code': 'DE',
            'country_name': 'country_name',
            'continent': 'EU',
            'time_zone': 'time_zone',
            'ISP': 'ISP',
            'staging_area': True,
            'rse_type': 'DISK',
            'longitude': 1.0,
            'latitude': 2.0
        }
        properties.update({'vo': vo})
        rse_id = add_rse(rse_name, **properties)
        assert rse_exists(rse=rse_name, vo=vo)
        rse = get_rse(rse_id=rse_id)
        assert rse['rse'] == rse_name
        assert rse['deterministic'] == properties['deterministic']
        assert rse['volatile'] == properties['volatile']
        assert rse['city'] == properties['city']
        assert rse['region_code'] == properties['region_code']
        assert rse['country_name'] == properties['country_name']
        assert rse['continent'] == properties['continent']
        assert rse['time_zone'] == properties['time_zone']
        assert rse['ISP'] == properties['ISP']
        assert rse['staging_area'] == properties['staging_area']
        assert rse['rse_type'] == RSEType.DISK
        assert rse['longitude'] == properties['longitude']
        assert rse['latitude'] == properties['latitude']
        assert rse['ASN'] == properties['ASN']
        assert rse['availability_read'] == properties['availability_read']
        assert rse['availability_write'] == properties['availability_write']
        assert rse['availability_delete'] == properties['availability_delete']
        assert not rse_exists(invalid_rse, vo=vo)

        with pytest.raises(Duplicate):
            add_rse(rse_name, vo=vo)
        del_rse(rse_id=rse_id)
        assert not rse_exists(rse=rse_name, vo=vo)

    def test_list_rses(self, vo):
        """ RSE (CORE): Test the listing of all RSEs """
        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        assert rse_exists(rse=rse, vo=vo)
        add_rse_attribute(rse_id=rse_id, key='tier', value='1')
        rses = list_rses(filters={'tier': '1'})
        assert (rse_id, rse) in [(r['id'], r['rse']) for r in rses]
        add_rse_attribute(rse_id=rse_id, key='country', value='us')

        rses = list_rses(filters={'tier': '1', 'country': 'us'})
        assert (rse_id, rse) in [(r['id'], r['rse']) for r in rses]

        del_rse(rse_id)

    @pytest.mark.dirty
    def test_list_rse_attributes(self, vo):
        """ RSE (CORE): Test the listing of RSE attributes """
        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        add_rse_attribute(rse_id=rse_id, key='tier', value='1')
        attr = list_rse_attributes(rse_id=rse_id)
        assert 'tier' in list(attr.keys())
        assert rse in list(attr.keys())

    def test_create_and_check_rse_transfer_limits(self, vo):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE transfer limit"""
        rse = rse_name_generator()
        activity = 'MOCk'
        max_transfers = 100
        transfers = 90
        waitings = 20
        rse_id = add_rse(rse, vo=vo)

        set_transfer_limit(rse_expression=rse, activity=activity, max_transfers=max_transfers, transfers=transfers, waitings=waitings)
        limits = get_rse_transfer_limits(rse_id=rse_id, activity=activity)
        [limits] = list(limits.values())
        assert activity in list(limits.keys())
        assert max_transfers == limits[activity]['max_transfers']
        assert transfers == limits[activity]['transfers']
        assert waitings == limits[activity]['waitings']

        set_transfer_limit(rse_expression=rse, activity=activity, max_transfers=max_transfers + 1, transfers=transfers + 1, waitings=waitings + 1)
        limits = get_rse_transfer_limits(rse_id=rse_id, activity=activity)
        [limits] = list(limits.values())
        assert activity in list(limits.keys())
        assert max_transfers + 1 == limits[activity]['max_transfers']
        assert transfers + 1 == limits[activity]['transfers']
        assert waitings + 1 == limits[activity]['waitings']

        delete_transfer_limit(rse_expression=rse, activity=activity)
        limits = get_rse_transfer_limits(rse_id=rse_id, activity=activity)
        assert not limits or activity not in limits or rse_id not in limits[activity]

        del_rse(rse_id=rse_id)

    @pytest.mark.dirty
    def test_delete_rse_attribute(self, vo):
        """ RSE (CORE): Test the deletion of a RSE attribute. """
        rse_name = rse_name_generator()
        rse_id = add_rse(rse_name, vo=vo)
        del_rse_attribute(rse_id=rse_id, key=rse_name)
        assert get_rse_attribute(rse_id, rse_name) is None

        with pytest.raises(RSEAttributeNotFound):
            del_rse_attribute(rse_id=rse_id, key=rse_name)

    @pytest.mark.dirty
    def test_delete_rse(self, vo):
        """ RSE (CORE): Test deletion of RSE """
        # Deletion of not empty RSE
        rse_name = rse_name_generator()
        rse_id = add_rse(rse_name, vo=vo)
        db_session = session.get_session()
        rse_usage = db_session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').one()
        rse_usage.used = 1
        db_session.commit()
        with pytest.raises(RSEOperationNotSupported):
            del_rse(rse_id)

        # Deletion of not found RSE:
        # rse_name = rse_name_generator() #- No longer valid syntax
        # with pytest.raises(RSENotFound):
        #     del_rse(rse=rse_name)

    @pytest.mark.dirty
    def test_restore_rse(self, vo):
        """ RSE (CORE): Test restore of RSE """
        # Restore deleted RSE
        rse_name = rse_name_generator()
        rse_id = add_rse(rse_name, vo=vo)
        db_session = session.get_session()
        db_session.commit()

        del_rse(rse_id)
        db_session.commit()
        # Verify RSE was deleted
        assert not rse_exists(rse=rse_name, vo=vo)

        restore_rse(rse_id=rse_id)
        db_session.commit()
        # Verify RSE was restored
        assert rse_exists(rse=rse_name, vo=vo)

        # Restoration of not deleted RSE:
        rse_name = rse_name_generator()
        rse_id = add_rse(rse_name, vo=vo)
        with pytest.raises(RSENotFound):
            restore_rse(rse_id=rse_id)

    @pytest.mark.dirty
    def test_empty_rse(self, vo):
        """ RSE (CORE): Test if RSE is empty """
        rse_name = rse_name_generator()
        rse_id = add_rse(rse_name, vo=vo)
        assert rse_is_empty(rse_id=rse_id)

        db_session = session.get_session()
        rse_usage = db_session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').one()
        rse_usage.used = 1
        db_session.commit()
        assert not rse_is_empty(rse_id=rse_id)


def test_parse_checksum_support_attribute():
    assert parse_checksum_support_attribute('') == GLOBALLY_SUPPORTED_CHECKSUMS
    assert parse_checksum_support_attribute('none') == []
    assert parse_checksum_support_attribute('none,md5') == []
    assert parse_checksum_support_attribute('md5') == ['md5']
    assert parse_checksum_support_attribute('md5,adler32') == ['md5', 'adler32']


@pytest.mark.parametrize("caches_mock", [{
    "caches_to_mock": ['rucio.core.rse.REGION'],
    'expiration_time': 0
}], indirect=True)
def test_rse_get_supported_checksums_from_attributes(vo, caches_mock):
    rse_name = rse_name_generator()
    rse_id = add_rse(rse_name, vo=vo)

    attrs = list_rse_attributes(rse_id)
    assert get_rse_supported_checksums_from_attributes(attrs) == GLOBALLY_SUPPORTED_CHECKSUMS

    add_rse_attribute(rse_id, CHECKSUM_KEY, 'none')
    attrs = list_rse_attributes(rse_id)
    assert get_rse_supported_checksums_from_attributes(attrs) == []

    add_rse_attribute(rse_id, CHECKSUM_KEY, 'md5')
    attrs = list_rse_attributes(rse_id)
    assert get_rse_supported_checksums_from_attributes(attrs) == ['md5']

    add_rse_attribute(rse_id, CHECKSUM_KEY, 'md5,adler32')
    attrs = list_rse_attributes(rse_id)
    assert get_rse_supported_checksums_from_attributes(attrs) == ['md5', 'adler32']

    del_rse(rse_id)


def test_create_rse_success(vo, rest_client, auth_token):
    """ RSE (REST): send a POST to create a new RSE """
    rse_name = rse_name_generator()
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
    properties = {
        'ASN': 'ASN',
        'availability_read': False,
        'availability_write': True,
        'availability_delete': False,
        'deterministic': True,
        'volatile': True,
        'city': 'city',
        'region_code': 'DE',
        'country_name': 'country_name',
        'continent': 'EU',
        'time_zone': 'time_zone',
        'ISP': 'ISP',
        'staging_area': True,
        'rse_type': 'DISK',
        'longitude': 1.0,
        'latitude': 2.0
    }
    response = rest_client.post('/rses/' + rse_name, headers=headers(auth(auth_token), hdrdict(headers_dict)), json=properties)
    assert response.status_code == 201
    rse = get_rse(rse_id=get_rse_id(rse=rse_name, vo=vo))
    assert rse['rse'] == rse_name
    assert rse['deterministic'] == properties['deterministic']
    assert rse['volatile'] == properties['volatile']
    assert rse['city'] == properties['city']
    assert rse['region_code'] == properties['region_code']
    assert rse['country_name'] == properties['country_name']
    assert rse['continent'] == properties['continent']
    assert rse['time_zone'] == properties['time_zone']
    assert rse['ISP'] == properties['ISP']
    assert rse['staging_area'] == properties['staging_area']
    assert rse['rse_type'] == RSEType.DISK
    assert rse['longitude'] == properties['longitude']
    assert rse['latitude'] == properties['latitude']
    assert rse['ASN'] == properties['ASN']
    assert rse['availability_read'] == properties['availability_read']
    assert rse['availability_write'] == properties['availability_write']
    assert rse['availability_delete'] == properties['availability_delete']

    response = rest_client.post('/rses/' + rse_name, headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 409


def xtest_tag_rses(rse_factory, rest_client, auth_token):
    """ RSE (REST): send a POST to tag a RSE """
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
    rse, _ = rse_factory.make_rse()
    data = {'rse': rse}
    response = rest_client.post('/rses/', headers=headers(auth(auth_token), hdrdict(headers_dict)), json=data)
    assert response.status_code == 201

    data = {'tag': 'MOCK_TAG'}
    response = rest_client.post('/rses/MOCK/tags', headers=headers(auth(auth_token), hdrdict(headers_dict)), json=data)
    assert response.status_code == 201


def xtest_list_rse_tags(rse_factory, rest_client, auth_token):
    """ RSE (REST): Test the listing of RSE tags """
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
    rse, _ = rse_factory.make_rse()
    data = {'rse': 'MOCK'}
    response = rest_client.post('/rses/', headers=headers(auth(auth_token), hdrdict(headers_dict)), json=data)
    assert response.status_code == 201

    data = {'tag': 'MOCK_TAG'}
    response = rest_client.post('/rses/MOCK/tags', headers=headers(auth(auth_token), hdrdict(headers_dict)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/rses/MOCK/tags', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 200


def test_get_rse_account_usage(rse_factory, rest_client, auth_token):
    """ RSE (REST): Test of RSE account usage and limit """
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}
    rse, _ = rse_factory.make_rse()
    response = rest_client.get(f'/rses/{rse}/accounts/usage', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 200


@pytest.mark.dirty
def test_delete_rse_attribute(vo, rest_client, auth_token):
    """ RSE (REST): Test the deletion of a RSE attribute """
    rse_name = rse_name_generator()
    add_rse(rse_name, vo=vo)
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}

    response = rest_client.delete('/rses/{0}/attr/{0}'.format(rse_name), headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 200

    response = rest_client.delete('/rses/{0}/attr/{0}'.format(rse_name), headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 404


@pytest.mark.dirty
def test_delete_rse(vo, rest_client, auth_token):
    """ RSE (REST): Test the deletion of RSE """
    # Normal deletion
    rse_name = rse_name_generator()
    add_rse(rse_name, vo=vo)
    headers_dict = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root'}

    response = rest_client.delete('/rses/{0}'.format(rse_name), headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 200
    # Second deletion
    response = rest_client.delete('/rses/{0}'.format(rse_name), headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 404
    # Deletion of not found RSE
    rse_name = rse_name_generator()
    response = rest_client.delete('/rses/{0}'.format(rse_name), headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 404
    # Deletion of not empty RSE
    rse_name = rse_name_generator()
    rse_id = add_rse(rse_name, vo=vo)
    db_session = session.get_session()
    rse_usage = db_session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').one()
    rse_usage.used = 1
    db_session.commit()
    response = rest_client.delete('/rses/{0}'.format(rse_name), headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 404
    assert response.headers.get('ExceptionClass') == 'RSEOperationNotSupported'


@pytest.mark.noparallel(reason='uses pre-defined RSE, fails when run in parallel')
class TestRSEClient:

    def test_add_rse(self, vo, rucio_client):
        """ RSE (CLIENTS): add a new rse."""
        rse_name = rse_name_generator()
        properties = {
            'ASN': 'ASN',
            'availability_read': False,
            'availability_write': True,
            'availability_delete': False,
            'deterministic': True,
            'volatile': True,
            'city': 'city',
            'region_code': 'DE',
            'country_name': 'country_name',
            'continent': 'EU',
            'time_zone': 'time_zone',
            'ISP': 'ISP',
            'staging_area': True,
            'rse_type': 'TAPE',
            'longitude': 1.0,
            'latitude': 2.0
        }
        ret = rucio_client.add_rse(rse_name, **properties)
        assert ret
        rse = get_rse(rse_id=get_rse_id(rse=rse_name, vo=vo))
        assert rse['rse'] == rse_name
        assert rse['deterministic'] == properties['deterministic']
        assert rse['volatile'] == properties['volatile']
        assert rse['city'] == properties['city']
        assert rse['region_code'] == properties['region_code']
        assert rse['country_name'] == properties['country_name']
        assert rse['continent'] == properties['continent']
        assert rse['time_zone'] == properties['time_zone']
        assert rse['ISP'] == properties['ISP']
        assert rse['staging_area'] == properties['staging_area']
        assert rse['rse_type'] == RSEType.TAPE
        assert rse['longitude'] == properties['longitude']
        assert rse['latitude'] == properties['latitude']
        assert rse['ASN'] == properties['ASN']
        assert rse['availability_read'] == properties['availability_read']
        assert rse['availability_write'] == properties['availability_write']
        assert rse['availability_delete'] == properties['availability_delete']

        with pytest.raises(Duplicate):
            rucio_client.add_rse(rse_name)

        bad_rse = 'MOCK_$*&##@!'
        with pytest.raises(InvalidObject):
            ret = rucio_client.add_rse(bad_rse)

    def test_update_rse(self, vo, rucio_client):
        """ RSE (CLIENTS): update rse."""
        # Check if updating RSE does not remove RSE tag
        rse = rse_name_generator()
        ret = rucio_client.add_rse(rse)
        assert get_rse_attribute(get_rse_id(rse, vo=vo), rse) is True
        rucio_client.update_rse(rse, {'availability_write': False, 'availability_delete': False})
        assert get_rse_attribute(get_rse_id(rse, vo=vo), rse) is True

        rse = rse_name_generator()
        renamed_rse = 'renamed_rse%s' % rse
        ret = rucio_client.add_rse(rse)
        assert ret

        ret = rucio_client.update_rse(rse, {'name': renamed_rse})
        assert ret
        dict2 = rucio_client.get_rse(renamed_rse)
        assert renamed_rse == dict2['rse']

        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': did_name_generator('file'), 'bytes': 1,
                   'adler32': '0cc737eb', 'meta': {'events': 10}} for i in range(nbfiles)]
        replica_client = ReplicaClient()
        replica_client.add_replicas(rse=renamed_rse, files=files1)

        ret = rucio_client.update_rse(renamed_rse, {'availability_write': False, 'availability_delete': False})
        assert ret
        dict2 = rucio_client.get_rse(renamed_rse)
        assert dict2['availability_write'] is False
        assert dict2['availability_delete'] is False

        files2 = [{'scope': tmp_scope, 'name': did_name_generator('file'), 'bytes': 1,
                   'adler32': '0cc737eb', 'meta': {'events': 10}} for i in range(nbfiles)]
        with pytest.raises(ResourceTemporaryUnavailable):
            replica_client.add_replicas(rse=renamed_rse, files=files2, ignore_availability=False)

    def test_update_rse_availability_all_false(self, rucio_client):
        """ RSE (CLIENTS): update rse should be able to set all availability options to False."""
        rse = rse_name_generator()
        ret = rucio_client.add_rse(rse)
        assert ret
        rucio_client.update_rse(rse, {"availability_read": False, "availability_write": False, "availability_delete": False})

    def test_list_rses(self, rucio_client):
        """ RSE (CLIENTS): try to list rses."""
        rse_list = [rse_name_generator() for i in range(5)]
        for rse in rse_list:
            rucio_client.add_rse(rse)

        svr_list = [r['rse'] for r in rucio_client.list_rses()]

        for rse in rse_list:
            assert rse in svr_list

    def test_get_rse(self, rucio_client):
        """ RSE (CLIENTS): Get a RSE."""
        id_ = 'MOCK'
        props = rucio_client.get_rse(rse=id_)
        assert props['rse'] == id_

    # ADD PROTOCOLS

    def test_add_protocol(self, vo, rucio_client):
        """ RSE (CLIENTS): add three protocols to rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 4,
                                  'write': 1,
                                  'delete': None}
                      },
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 18,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 20,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 2,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)
        resp = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        for p in resp['protocols']:
            if ((p['port'] == 19) and (p['domains']['lan']['read'] != 1)) or \
                    ((p['port'] == 20) and (p['domains']['lan']['read'] != 2)) or \
                    ((p['port'] == 18) and (p['domains']['lan']['read'] != 1)) or \
                    ((p['port'] == 17) and (p['domains']['lan']['read'] != 4)):
                print(resp)
                assert False

        rucio_client.delete_protocols(protocol_rse, scheme='MOCK')
        rucio_client.delete_rse(protocol_rse)

    def test_add_protocol_rse_not_found(self, rucio_client):
        """ RSE (CLIENTS): add a protocol to an rse that does not exist (RSENotFound)."""
        attributes = {'hostname': 'localhost',
                      'scheme': 'MOCK_Fail',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}
        with pytest.raises(RSENotFound):
            rucio_client.add_protocol('The One that shouldn\'t be here', attributes)

    def test_add_protocol_missing_values(self, rucio_client):
        """ RSE (CLIENTS): add a protocol with insufficient parameters (InvalidObject)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        attributes = {'hostname': 'localhost',
                      'scheme': 'MOCK_Fail',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      # 'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}
        try:
            with pytest.raises(exception.InvalidObject):
                rucio_client.add_protocol(protocol_rse, attributes)
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_add_protocol_duplicate(self, rucio_client):
        """ RSE (CLIENTS): add duplicate protocol to rse (Duplicate)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        attributes = {'hostname': 'localhost',
                      'scheme': 'MOCK_Duplicate',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}
        try:
            rucio_client.add_protocol(protocol_rse, attributes)
            with pytest.raises(exception.Duplicate):
                rucio_client.add_protocol(protocol_rse, attributes)
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_add_protocol_not_suppotred_domain(self, rucio_client):
        """ RSE (CLIENTS): add a protocol with unsupported domain parameters (RSEProtocolDomainNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        attributes = {'hostname': 'localhost',
                      'scheme': 'Mock_Insuff_Params',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      # 'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'FIRENDS': {'read': 1,
                                      'write': 1,
                                      'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}
        try:
            with pytest.raises(exception.RSEProtocolDomainNotSupported):
                rucio_client.add_protocol(protocol_rse, attributes)
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_add_protocol_wrong_priority(self, rucio_client):
        """ RSE (CLIENTS): Add a protocol with an invalid priority for ranking. """
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocol_ports = [17, 29, 42]
        for i in range(3):
            attributes = {'hostname': 'localhost',
                          'scheme': 'MOCK',
                          'port': protocol_ports[i],
                          'prefix': '/the/one/with/all/the/files',
                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                          'domains': {
                              'lan': {'read': 1,
                                      'write': 1,
                                      'delete': 1}},
                          'extended_attributes': 'TheOneWithAllTheRest'}
            rucio_client.add_protocol(protocol_rse, attributes)
        try:
            attributes = {'hostname': 'localhost',
                          'scheme': 'MOCK',
                          'port': 815,
                          'prefix': '/the/one/with/all/the/files',
                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                          'domains': {
                              'lan': {'read': 4,
                                      'write': 99,
                                      'delete': -1}},
                          'extended_attributes': 'TheOneWithAllTheRest'}
            with pytest.raises(exception.RSEProtocolPriorityError):
                rucio_client.add_protocol(protocol_rse, attributes)
        finally:
            rucio_client.delete_rse(protocol_rse)

    # DELETE PROTOCOLS

    def test_del_protocol_rse_not_found(self, rucio_client):
        """ RSE (CLIENTS): delete a protocol from an rse that does not exist (RSENotFound)."""
        with pytest.raises(RSENotFound):
            rucio_client.delete_protocols('The One that shouldn\'t be here', 'MOCK_Fail')

    def test_del_protocol_id(self, vo, rucio_client):
        """ RSE (CLIENTS): delete multiple protocols with the same identifier from an rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_ID_SUCCESS'
        protocol_ports = [17, 29, 42]
        for i in range(3):
            attributes = {'hostname': 'localhost',
                          'scheme': protocol_id,
                          'port': protocol_ports[i],
                          'prefix': '/the/one/with/all/the/files',
                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                          'domains': {
                              'lan': {'read': 1,
                                      'write': 1,
                                      'delete': 1}}}
            rucio_client.add_protocol(protocol_rse, attributes)

        try:
            rucio_client.delete_protocols(protocol_rse, protocol_id)

            # check if empty
            resp = mgr.get_rse_info(rse=protocol_rse, vo=vo)
            with pytest.raises(RSEProtocolNotSupported):
                mgr.select_protocol(resp, 'read', scheme=protocol_id)
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_del_protocol_id_protocol_not_supported(self, rucio_client):
        """ RSE (CLIENTS): delete a none-existing protocol from an rse (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        try:
            with pytest.raises(exception.RSEProtocolNotSupported):
                rucio_client.delete_protocols(protocol_rse, 'MOCK_Fail')
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_del_protocol_hostname(self, vo, rucio_client):
        """ RSE (CLIENTS): delete multiple protocols with the same identifier, and the same hostname from an rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_HOST_SUCCESS'
        protocol_hostname = ['localhost', 'an_other_host', 'localhost']
        protocol_ports = [17, 29, 42]
        for i in range(3):
            attributes = {'hostname': protocol_hostname[i],
                          'scheme': protocol_id,
                          'port': protocol_ports[i],
                          'prefix': '/the/one/with/all/the/files',
                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                          'domains': {
                              'lan': {'read': 1,
                                      'write': 1,
                                      'delete': 1}},
                          'extended_attributes': 'TheOneWithAllTheRest'}
            rucio_client.add_protocol(protocol_rse, attributes)
        rucio_client.delete_protocols(protocol_rse, scheme=protocol_id, hostname='localhost')

        # check if protocol for 'other_host' are still there
        resp = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        for r in resp['protocols']:
            if r['hostname'] == 'localhost':
                rucio_client.delete_rse(protocol_rse)
                raise Exception('Protocols not deleted. Remaining: %s' % resp)

        rucio_client.delete_protocols(protocol_rse, scheme=protocol_id, hostname='an_other_host')
        rucio_client.delete_rse(protocol_rse)

    def test_del_protocol_hostname_protocol_not_supported(self, rucio_client):
        """ RSE (CLIENTS): delete a non-existing protocol from an rse with given hostname (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        try:
            attributes = {'hostname': 'localhost',
                          'scheme': 'MOCK_PROTOCOL_DEL_HOST_FAIL',
                          'port': 42,
                          'prefix': '/the/one/with/all/the/files',
                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                          'domains': {
                              'lan': {'read': 1,
                                      'write': 1,
                                      'delete': 1}},
                          'extended_attributes': 'TheOneWithAllTheRest'}
            rucio_client.add_protocol(protocol_rse, attributes)

            with pytest.raises(exception.RSEProtocolNotSupported):
                rucio_client.delete_protocols(protocol_rse, attributes['scheme'], hostname='an_other_host')

            rucio_client.delete_protocols(protocol_rse, attributes['scheme'], hostname=attributes['hostname'])
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_del_protocol_port(self, vo, rucio_client):
        """ RSE (CLIENTS): delete a specific protocol from an rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_PORT_SUCCESS'
        protocol_hostname = ['localhost', 'an_other_host', 'localhost']
        protocol_ports = [17, 29, 42]
        for i in range(3):
            attributes = {'hostname': protocol_hostname[i],
                          'scheme': protocol_id,
                          'port': protocol_ports[i],
                          'prefix': '/the/one/with/all/the/files',
                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                          'domains': {
                              'lan': {'read': 1,
                                      'write': 1,
                                      'delete': 1}},
                          'extended_attributes': 'TheOneWithAllTheRest'}
            rucio_client.add_protocol(protocol_rse, attributes)
        rucio_client.delete_protocols(protocol_rse, scheme=protocol_id, hostname='localhost', port=17)

        # check remaining protocols
        resp = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        for r in resp['protocols']:
            if r['port'] == 17:
                rucio_client.delete_protocols(protocol_rse, protocol_id)
                rucio_client.delete_rse(protocol_rse)
                raise Exception('Protocols not deleted. Remaining: %s' % resp)
        rucio_client.delete_protocols(protocol_rse, protocol_id)
        rucio_client.delete_rse(protocol_rse)

    def test_del_protocol_port_protocol_not_supported(self, rucio_client):
        """ RSE (CLIENTS): delete a specific protocol from an rse. (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        attributes = {'hostname': 'localhost',
                      'scheme': 'MOCK_PROTOCOL_DEL_PORT_FAIL',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}
        rucio_client.add_protocol(protocol_rse, attributes)
        try:
            with pytest.raises(exception.RSEProtocolNotSupported):
                rucio_client.delete_protocols(protocol_rse, 'MOCK_Fail', hostname='localhost', port=17)
        finally:
            rucio_client.delete_rse(protocol_rse)

    # GET PROTOCOLS

    def test_get_protocols(self, vo, rucio_client):
        """ RSE (CLIENTS): get protocols of rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_READ',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1},
                          'wan': {'read': None,
                                  'write': None,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1},
                          'wan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': None,
                                  'delete': 1},
                          'wan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)
        # GET all = 3
        resp = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        if len(resp['protocols']) != 3:
            for p in protocols:
                rucio_client.delete_protocols(protocol_rse, p['scheme'])
            rucio_client.delete_rse(protocol_rse)
            raise Exception('Unexpected protocols returned: %s' % resp)
        for p in protocols:
            rucio_client.delete_protocols(protocol_rse, p['scheme'])
        rucio_client.delete_rse(protocol_rse)

    def test_get_protocols_rse_not_found(self, vo):
        """ RSE (CLIENTS): get all protocols of rse (RSENotFound)."""
        with pytest.raises(RSENotFound):
            mgr.get_rse_info(rse="TheOnethatshouldnotbehere", vo=vo)

    def test_get_protocols_operations(self, vo, rucio_client):
        """ RSE (CLIENTS): get protocols for operations of rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_READ_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': None,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol identifier include supported operations
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        ops = {'read': 1, 'write': 2, 'delete': 3}
        rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        for op in ops:
            # resp = rucio_client.get_protocols(protocol_rse, operation=op, protocol_domain='lan')
            p = mgr.select_protocol(rse_attr, op, domain='lan')
            if op not in p['scheme'].lower():
                for p in protocols:
                    rucio_client.delete_protocols(protocol_rse, p['scheme'])
                rucio_client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, p))
        for p in protocols:
            rucio_client.delete_protocols(protocol_rse, p['scheme'])
        rucio_client.delete_rse(protocol_rse)

    def test_get_protocols_defaults(self, vo, rucio_client):
        """ RSE (CLIENTS): get default protocols for operations of rse."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_READ',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1},
                          'wan': {'delete': 1}
                      },
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'write': 1},
                          'wan': {'read': 1}
                      },
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'delete': 1},
                          'wan': {'write': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        for op in ['delete', 'read', 'write']:
            # resp = rucio_client.get_protocols(protocol_rse, operation=op, default=True, protocol_domain='lan')
            p = mgr.select_protocol(rse_attr, op, domain='lan')
            print(p['scheme'])
            print(op)
            if op not in p['scheme'].lower():
                for p in protocols:
                    rucio_client.delete_protocols(protocol_rse, p['scheme'])
                rucio_client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, p))
        for op in ['delete', 'read', 'write']:
            # resp = rucio_client.get_protocols(protocol_rse, operation=op, default=True, protocol_domain='wan')
            p = mgr.select_protocol(rse_attr, op, domain='wan')
            if ((op == 'delete') and (p['port'] != 17)) or ((op == 'read') and (p['port'] != 42)) or ((op == 'write') and (p['port'] != 19)):
                for p in protocols:
                    rucio_client.delete_protocols(protocol_rse, p['scheme'])
                rucio_client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, p))
        for p in protocols:
            rucio_client.delete_protocols(protocol_rse, p['scheme'])
        rucio_client.delete_rse(protocol_rse)

    def test_get_protocols_nested_attributes(self, vo, rucio_client):
        """ RSE (CLIENTS): get nested extended_attributes."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_READ',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1},
                          'wan': {'delete': 1}
                      },
                      'extended_attributes': {'Some': 'value', 'more': {'value1': 1, 'value2': 0}}}]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        resp = mgr.get_rse_info(rse=protocol_rse, vo=vo)['protocols']
        assert ((not resp[0]['extended_attributes']['more']['value2']) and resp[0]['extended_attributes']['more']['value1'])

    def test_get_protocols_operations_not_supported(self, vo, rucio_client):
        """ RSE (CLIENTS): get protocols for operations of rse (RSEOperationNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': None,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
            rse_attr['domain'] = ['lan']
            with pytest.raises(exception.RSEProtocolNotSupported):
                mgr.select_protocol(rse_attr, 'read')
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_get_protocols_domain_not_exist(self, vo, rucio_client):
        """ RSE (CLIENTS): get protocols for operations of rse in not existing domain (RSEProtocolDomainNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        attributes = {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}
        # Protocol for read is undefined
        rucio_client.add_protocol(protocol_rse, attributes)

        try:
            rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
            with pytest.raises(exception.RSEProtocolDomainNotSupported):
                mgr.select_protocol(rse_attr, 'write', domain='FRIENDS')
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_get_protocols_domain_not_supported(self, vo, rucio_client):
        """ RSE (CLIENTS): get protocols for operations of rse in unsupported domain (RSEOperationNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
            rse_attr['domain'] = ['wan']
            with pytest.raises(exception.RSEProtocolNotSupported):
                mgr.select_protocol(rse_attr, 'write')
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_get_protocols_defaults_not_supported(self, vo, rucio_client):
        """ RSE (CLIENTS): get default protocols for operations of rse (RSEOperationNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': None,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
            rse_attr['domain'] = ['lan']
            with pytest.raises(exception.RSEProtocolNotSupported):
                mgr.select_protocol(rse_attr, 'read')
        finally:
            rucio_client.delete_rse(protocol_rse)

    # UPDATE PROTOCOLS

    def test_update_protocols_port_exist(self, rucio_client):
        """ RSE (CLIENTS): set new values for various protocol attributes."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'wan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 11,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'wan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'}]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        try:
            with pytest.raises(exception.Duplicate):
                rucio_client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=17, data={'prefix': 'where/the/files/are', 'extended_attributes': 'Something else', 'port': '11'})
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_update_protocols_various_attributes(self, vo, rucio_client):
        """ RSE (CLIENTS): set new values for various protocol attributes."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'}]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        rucio_client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=17, data={'prefix': 'where/the/files/are', 'extended_attributes': 'Something else', 'port': '12'})
        rse_attr = mgr.get_rse_info(rse=protocol_rse, vo=vo)
        p = mgr.select_protocol(rse_attr, 'read', scheme='MOCK', domain='lan')
        if p['prefix'] != 'where/the/files/are' and p['extended_attributes'] != 'Something else':
            raise Exception('Update gave unexpected results: %s' % p)
        rucio_client.delete_protocols(protocol_rse, 'MOCK')
        rucio_client.delete_rse(protocol_rse)

    def test_swap_protocol(self, rucio_client):
        """ RSE (CLIENTS): swaps the priority of two protocols by scheme. """
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCKA',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCKB',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 2,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCKC',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 3,
                                  'write': None,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        rucio_client.swap_protocols(protocol_rse, 'lan', 'read', 'MOCKA', 'MOCKC')
        prots = rucio_client.get_protocols(protocol_rse)
        for p in prots:
            if p['scheme'] == 'MOCKA':
                if p['domains']['lan']['read'] != 3:
                    print('MOCKA with unexpected priority')
                    print(prots)
                    assert False
            if p['scheme'] == 'MOCKC':
                if p['domains']['lan']['read'] != 1:
                    print('MOCKC with unexpected priority')
                    print(prots)
                    assert False
        assert True

    def test_update_protocols_rse_not_found(self, rucio_client):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse (RSENotFound)."""
        with pytest.raises(RSENotFound):
            rucio_client.update_protocols('The One that shouldn\'t be here', scheme='MOCK_Fail', hostname='localhost', port=17, data={'prefix': 'where/the/files/are'})

    def test_update_protocols_not_supported(self, rucio_client):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': None,
                                  'write': None,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            rucio_client.add_protocol(protocol_rse, p)

        try:
            with pytest.raises(exception.RSEProtocolNotSupported):
                rucio_client.update_protocols(protocol_rse, scheme='MOCK_UNDEFINED', hostname='localhost', port=17, data={'delete_lan': 1})
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_update_protocols_invalid_value(self, rucio_client):
        """ RSE (CLIENTS): update all protocol with invalid value (InvalidObject)."""
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        attributes = {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      # 'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {'lan': {'read': 1,
                                          'write': 1,
                                          'delete': None}},
                      'extended_attributes': 'TheOneWithAllTheRest'}

        try:
            with pytest.raises(exception.InvalidObject):
                rucio_client.add_protocol(protocol_rse, attributes)

            with pytest.raises(exception.RSEProtocolNotSupported):
                rucio_client.update_protocols(protocol_rse, scheme=attributes['scheme'], hostname=attributes['hostname'], port=attributes['port'], data={'impl': None})
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_update_protocol_wrong_priority(self, rucio_client):
        """  RSE (CLIENTS): Add a protocol with an invalid priority for ranking. """
        protocol_rse = rse_name_generator()
        rucio_client.add_rse(protocol_rse)
        protocol_ports = [17, 29, 42]
        for i in range(3):
            rucio_client.add_protocol(protocol_rse,
                                      {'hostname': 'localhost',
                                       'scheme': 'MOCK',
                                       'port': protocol_ports[i],
                                       'prefix': '/the/one/with/all/the/files',
                                       'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                       'domains': {
                                           'lan': {'read': 1,
                                                   'write': 1,
                                                   'delete': 1}},
                                       'extended_attributes': 'TheOneWithAllTheRest'})
        try:
            with pytest.raises(exception.RSEProtocolPriorityError):
                rucio_client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=42, data={'domains': {'lan': {'read': -1}}})
        finally:
            rucio_client.delete_rse(protocol_rse)

    def test_get_rse_usage(self, vo, rucio_client, rse_factory, jdoe_account, root_account, mock_scope):
        """ RSE (CLIENTS): Test getting the RSE usage. """
        file_sizes = 100
        nfiles = 3
        rse, rse_id = rse_factory.make_posix_rse()
        set_local_account_limit(account=jdoe_account, rse_id=rse_id, bytes_=10000)
        activity = get_schema_value('ACTIVITY')['enum'][0]
        files = create_files(nfiles, mock_scope, rse_id, bytes_=file_sizes)
        dataset = did_name_generator('dataset')
        add_did(mock_scope, dataset, DIDType.DATASET, jdoe_account)
        attach_dids(mock_scope, dataset, files, jdoe_account)
        rules = add_rule(dids=[{'scope': mock_scope, 'name': dataset}], account=jdoe_account, copies=1, rse_expression=rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, activity=activity)
        assert rules
        account_update(once=True)
        usages = rucio_client.get_rse_usage(rse=rse, filters={'per_account': True})
        for usage in usages:
            assert usage['account_usages']
        usages = rucio_client.get_rse_usage(rse=rse)
        for usage in usages:
            assert 'account_usages' not in usage
        account_usages = {u['account']: u for u in get_rse_account_usage(rse_id)}
        assert account_usages[jdoe_account]['quota_bytes'] == 10000
        assert account_usages[jdoe_account]['used_files'] == nfiles
        assert account_usages[jdoe_account]['used_bytes'] == nfiles * file_sizes
        assert not account_usages[root_account]['quota_bytes']
        assert account_usages[root_account]['used_files'] == 0
        assert account_usages[root_account]['used_bytes'] == 0

    @pytest.mark.dirty("creates a new RSE")
    def test_set_rse_usage(self, rucio_client, rse_factory):
        """ RSE (CLIENTS): Test the update of RSE usage."""
        rse, _ = rse_factory.make_posix_rse()
        assert rucio_client.set_rse_usage(rse=rse, source='srm', used=999200, free=800)
        usages = rucio_client.get_rse_usage(rse=rse)
        for usage in usages:
            if usage['source'] == 'srm':
                assert usage['files'] is None
                assert usage['total'] == 1000000
        assert rucio_client.set_rse_usage(rse=rse, source='srm', used=999920, free=80, files=50)
        for usage in rucio_client.list_rse_usage_history(rse=rse):
            assert usage['free'] == 80
            assert usage['files'] == 50
            break

    def test_set_rse_limits(self, rse_factory, rucio_client):
        """ RSE (CLIENTS): Test the update of RSE limits."""
        rse, _ = rse_factory.make_posix_rse()
        assert rucio_client.set_rse_limits(rse=rse, name='MinFreeSpace', value=1000000)
        limits = rucio_client.get_rse_limits(rse=rse)
        assert limits['MinFreeSpace'] == 1000000

    def test_rsemgr_possible_protocols(self):
        """ RSE (MANAGER): Test of possible protocols."""
        rse_settings = {'availability_delete': True,
                        'availability_read': True,
                        'availability_write': True,
                        'credentials': None,
                        'deterministic': True,
                        'domain': ['lan', 'wan'],
                        'protocols': [{'domains': {'lan': {'delete': 2, 'read': None, 'write': None},
                                                   'wan': {'delete': 2, 'read': 2, 'write': None}},
                                       'extended_attributes': None,
                                       'hostname': 'atlas-xrd.gridpp.rl.ac.uk',
                                       'impl': 'rucio.rse.protocols.gfal.Default',
                                       'port': 1094,
                                       'prefix': '//castor/ads.rl.ac.uk/prod/atlas/stripInput/atlasdatadisk/rucio/',
                                       'scheme': 'root'},
                                      {'domains': {'lan': {'delete': None, 'read': 1, 'write': None},
                                                   'wan': {'delete': None, 'read': None, 'write': None}},

                                       'extended_attributes': None,
                                       'hostname': 'catlasdlf.ads.rl.ac.uk',
                                       'impl': 'rucio.rse.protocols.gfal.Default',
                                       'port': 1094,
                                       'prefix': '//castor/ads.rl.ac.uk/prod/atlas/stripInput/atlasdatadisk/rucio/',
                                       'scheme': 'root'},
                                      {'domains': {'lan': {'delete': 1, 'read': None, 'write': 1},
                                                   'wan': {'delete': 1, 'read': 1, 'write': 1}},
                                       'extended_attributes': {'space_token': 'ATLASDATADISK',
                                                               'web_service_path': '/srm/managerv2?SFN='},
                                       'hostname': 'srm-atlas.gridpp.rl.ac.uk',
                                       'impl': 'rucio.rse.protocols.gfal.Default',
                                       'port': 8443,
                                       'prefix': '/castor/ads.rl.ac.uk/prod/atlas/stripInput/atlasdatadisk/rucio/',
                                       'scheme': 'srm'}],
                        'rse': 'MOCK',
                        'rse_type': 'DISK',
                        'staging_area': False,
                        'volatile': False}
        assert len(mgr._get_possible_protocols(rse_settings, 'read')) == 3

    @pytest.mark.dirty
    def test_add_distance(self, rucio_client):
        """ RSE (CLIENTS): add/get/update RSE distances."""
        source, destination = rse_name_generator(), rse_name_generator()
        rucio_client.add_rse(source)
        rucio_client.add_rse(destination)
        rucio_client.add_distance(source=source,
                                  destination=destination,
                                  parameters={'distance': 1})

        for distance in rucio_client.get_distance(source=source, destination=destination):
            assert distance['distance'] == 1

        rucio_client.update_distance(source=source,
                                     destination=destination,
                                     parameters={'distance': 0})

        for distance in rucio_client.get_distance(source=source, destination=destination):
            print(distance)
            assert distance['distance'] == 0

    def test_get_rse_protocols_includes_verify_checksum(self, vo):
        """ RSE (CORE): Test validate_checksum in RSEs info"""
        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        add_rse_attribute(rse_id=rse_id, key='verify_checksum', value=False)
        info = get_rse_protocols(rse_id)

        assert 'verify_checksum' in info
        assert info['verify_checksum'] is False

        del_rse(rse_id)

        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        add_rse_attribute(rse_id=rse_id, key='verify_checksum', value=True)
        info = get_rse_protocols(rse_id)

        assert 'verify_checksum' in info
        assert info['verify_checksum'] is True
        del_rse(rse_id)

    @pytest.mark.dirty
    def test_delete_rse_attribute(self, vo, rucio_client):
        """ RSE (CLIENT): Test the deletion of a RSE attribute. """
        rse_name = rse_name_generator()
        rucio_client.add_rse(rse_name)
        rucio_client.delete_rse_attribute(rse=rse_name, key=rse_name)
        assert get_rse_attribute(get_rse_id(rse_name, vo=vo), rse_name) is None

        with pytest.raises(RSEAttributeNotFound):
            rucio_client.delete_rse_attribute(rse=rse_name, key=rse_name)

    @pytest.mark.dirty
    def test_delete_rse(self, vo, rucio_client):
        """ RSE (CLIENTS): delete RSE """
        # Deletion of not empty RSE
        rse_name = rse_name_generator()
        add_rse(rse_name, vo=vo)
        rse_id = get_rse_id(rse_name, vo=vo)
        db_session = session.get_session()
        rse_usage = db_session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='rucio').one()
        rse_usage.used = 1
        db_session.commit()
        db_session = session.get_session()
        print(db_session.query(models.RSEUsage).filter_by(rse_id=rse_id).one())
        with pytest.raises(RSEOperationNotSupported):
            rucio_client.delete_rse(rse=rse_name)

        # Deletion of not found RSE:
        rse_name = rse_name_generator()
        with pytest.raises(RSENotFound):
            rucio_client.delete_rse(rse=rse_name)

    def test_rse_update_unsupported_option(self, vo):
        """ RSE(CLIENT): update with an unsupported option should throw an exception"""
        rse_name = rse_name_generator()
        add_rse(rse_name, vo=vo)
        rse_id = get_rse_id(rse_name, vo=vo)

        update_rse(rse_id, parameters={'city': 'Berlin'})
        assert get_rse(rse_id)['city'] == 'Berlin'

        with pytest.raises(InputValidationError):
            update_rse(rse_id, parameters={'city': 'Not Berlin', 'non_existing_option': 3})
        assert get_rse(rse_id)['city'] == 'Berlin'


@pytest.mark.parametrize("use_cache", [
    False,
    pytest.param(True, marks=pytest.mark.xfail(reason='FIXME: Calling functions which change the rse attribute should invalidate the cache.')),
])
def test_get_rse_attribute(use_cache, rse_factory):
    _, rse_id = rse_factory.make_mock_rse()

    assert get_rse_attribute(rse_id, "test") is None

    add_rse_attribute(rse_id, "test", "test")
    assert get_rse_attribute(rse_id, "test", use_cache=use_cache) == "test"

    add_rse_attribute(rse_id, "test", True)
    assert get_rse_attribute(rse_id, "test", use_cache=use_cache) is True

    add_rse_attribute(rse_id, "test", False)
    assert get_rse_attribute(rse_id, "test", use_cache=use_cache) is False

    del_rse_attribute(rse_id, "test")
    assert get_rse_attribute(rse_id, "test", use_cache=use_cache) is None
