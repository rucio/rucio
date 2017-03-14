'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
 - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
 - Martin Barisits, <martin.barisits@cern.ch>, 2013
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015
 - Ralph Vigne, <ralph.vigne@cern.ch>, 2013-2015
 - Wen Guan, <wen.guan@cern.ch>, 2015
'''

from json import dumps
from nose.tools import raises, assert_equal, assert_true, assert_in, assert_raises
from paste.fixture import TestApp

from rucio.client.rseclient import RSEClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.exception import (Duplicate, RSENotFound, RSEProtocolNotSupported,
                                    InvalidObject, RSEProtocolDomainNotSupported, RSEProtocolPriorityError, ResourceTemporaryUnavailable)
from rucio.common.utils import generate_uuid
from rucio.core.rse import (add_rse, get_rse_id, del_rse, list_rses, rse_exists, add_rse_attribute, list_rse_attributes,
                            set_rse_transfer_limits, get_rse_transfer_limits, delete_rse_transfer_limits)
from rucio.rse import rsemanager as mgr
from rucio.tests.common import rse_name_generator
from rucio.web.rest.rse import APP as rse_app
from rucio.web.rest.authentication import APP as auth_app


class TestRSECoreApi(object):

    def test_create_and_check_for_rse(self):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE """
        rse = rse_name_generator()
        invalid_rse = 'BLAHBLAH'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(rse_exists(invalid_rse), False)

        with assert_raises(Duplicate):
            add_rse(rse)
        del_rse(rse)

    def test_list_rses(self):
        """ RSE (CORE): Test the listing of all RSEs """
        rse = rse_name_generator()
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse_attribute(rse=rse, key='tier', value='1')
        rses = list_rses(filters={'tier': '1'})
        assert_in(rse, [r['rse'] for r in rses])
        add_rse_attribute(rse=rse, key='country', value='us')

        rses = list_rses(filters={'tier': '1', 'country': 'us'})
        assert_in(rse, [r['rse'] for r in rses])

        del_rse(rse)

    def test_list_rse_attributes(self):
        """ RSE (CORE): Test the listing of RSE attributes """
        rse = rse_name_generator()
        rse_id = add_rse(rse)
        add_rse_attribute(rse=rse, key='tier', value='1')
        attr = list_rse_attributes(rse=None, rse_id=rse_id)
        assert_in('tier', attr.keys())
        assert_in(rse, attr.keys())

    def test_create_and_check_rse_transfer_limits(self):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE transfer limit"""
        rse = rse_name_generator()
        activity = 'MOCk'
        max_transfers = 100
        transfers = 90
        waitings = 20
        add_rse(rse)
        rse_id = get_rse_id(rse)

        set_rse_transfer_limits(rse=rse, activity=activity, max_transfers=max_transfers, transfers=transfers, waitings=waitings)
        limits = get_rse_transfer_limits(rse=rse, activity=activity)
        assert_in(activity, limits.keys())
        assert_in(rse_id, limits[activity])
        assert_equal(max_transfers, limits[activity][rse_id]['max_transfers'])
        assert_equal(transfers, limits[activity][rse_id]['transfers'])
        assert_equal(waitings, limits[activity][rse_id]['waitings'])

        set_rse_transfer_limits(rse=rse, activity=activity, max_transfers=max_transfers + 1, transfers=transfers + 1, waitings=waitings + 1)
        limits = get_rse_transfer_limits(rse=rse, activity=activity)
        assert_in(activity, limits.keys())
        assert_in(rse_id, limits[activity])
        assert_equal(max_transfers + 1, limits[activity][rse_id]['max_transfers'])
        assert_equal(transfers + 1, limits[activity][rse_id]['transfers'])
        assert_equal(waitings + 1, limits[activity][rse_id]['waitings'])

        delete_rse_transfer_limits(rse=rse, activity=activity)
        limits = get_rse_transfer_limits(rse=rse, activity=activity)
        deleted = not limits or activity not in limits or rse_id not in limits[activity]
        assert_equal(deleted, True)

        del_rse(rse)


class TestRSE(object):

    def test_create_rse_success(self):
        """ RSE (REST): send a POST to create a new RSE """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))
        rse = rse_name_generator()
        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 409)

    def xtest_tag_rses(self):
        """ RSE (REST): send a POST to tag a RSE """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        data = dumps({'rse': 'MOCK'})
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        data = dumps({'tag': 'MOCK_TAG'})
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/MOCK/tags', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

    def xtest_list_rse_tags(self):
        """ RSE (REST): Test the listing of RSE tags """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        data = dumps({'rse': 'MOCK'})
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        data = dumps({'tag': 'MOCK_TAG'})
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/MOCK/tags', headers=headers3, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

        headers4 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r4 = TestApp(rse_app.wsgifunc(*mw)).get('/MOCK/tags', headers=headers4, expect_errors=True)
        assert_equal(r4.status, 200)

    def test_get_rse_account_usage(self):
        """ RSE (REST): Test of RSE account usage and limit """
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).get('/MOCK/accounts/usage', headers=headers2, expect_errors=True)
        assert_equal(r2.status, 200)


class TestRSEClient(object):

    def setup(self):
        self.client = RSEClient()

    def test_add_rse(self):
        """ RSE (CLIENTS): add a new rse."""
        rse = rse_name_generator()
        ret = self.client.add_rse(rse)
        assert_true(ret)

        with assert_raises(Duplicate):
            self.client.add_rse(rse)

        bad_rse = 'MOCK_$*&##@!'
        with assert_raises(InvalidObject):
            ret = self.client.add_rse(bad_rse)

    def test_update_rse(self):
        """ RSE (CLIENTS): update rse."""
        rse = rse_name_generator()
        renamed_rse = 'renamed_rse%s' % rse
        ret = self.client.add_rse(rse)
        assert_true(ret)

        ret = self.client.update_rse(rse, {'name': renamed_rse})
        assert_true(ret)
        dict2 = self.client.get_rse(renamed_rse)
        assert_equal(renamed_rse, dict2['rse'])

        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        replica_client = ReplicaClient()
        replica_client.add_replicas(rse=renamed_rse, files=files1)

        ret = self.client.update_rse(renamed_rse, {'availability_write': False, 'availability_delete': False})
        assert_true(ret)
        dict2 = self.client.get_rse(renamed_rse)
        assert_equal(dict2['availability_write'], False)
        assert_equal(dict2['availability_delete'], False)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        with assert_raises(ResourceTemporaryUnavailable):
            replica_client.add_replicas(rse=renamed_rse, files=files2, ignore_availability=False)

    def test_list_rses(self):
        """ RSE (CLIENTS): try to list rses."""
        rse_list = [rse_name_generator() for i in xrange(5)]
        for rse in rse_list:
            self.client.add_rse(rse)

        svr_list = [r['rse'] for r in self.client.list_rses()]

        for rse in rse_list:
            assert_in(rse, svr_list)

    def test_get_rse(self):
        """ RSE (CLIENTS): Get a RSE."""
        id = 'MOCK'
        props = self.client.get_rse(rse=id)
        assert props['rse'] == id

    # ADD PROTOCOLS

    def test_add_protocol(self):
        """ RSE (CLIENTS): add three protocols to rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 4,
                                  'write': 1,
                                  'delete': 0}
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
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 20,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 2,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)
        resp = mgr.get_rse_info(protocol_rse)
        for p in resp['protocols']:
            if ((p['port'] == 19) and (p['domains']['lan']['read'] != 1)) or \
               ((p['port'] == 20) and (p['domains']['lan']['read'] != 2)) or \
               ((p['port'] == 18) and (p['domains']['lan']['read'] != 1)) or \
               ((p['port'] == 17) and (p['domains']['lan']['read'] != 4)):
                print resp
                assert False

        self.client.delete_protocols(protocol_rse, scheme='MOCK')
        self.client.delete_rse(protocol_rse)

    @raises(RSENotFound)
    def test_add_protocol_rse_not_found(self):
        """ RSE (CLIENTS): add a protocol to an rse that does not exist (RSENotFound)."""
        self.client.add_protocol('The One that shouldn\'t be here',
                                 {'hostname': 'localhost',
                                  'scheme': 'MOCK_Fail',
                                  'port': 17,
                                  'prefix': '/the/one/with/all/the/files',
                                  'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'domains': {
                                      'lan': {'read': 1,
                                              'write': 1,
                                              'delete': 1}},
                                  'extended_attributes': 'TheOneWithAllTheRest'})

    @raises(InvalidObject)
    def test_add_protocol_missing_values(self):
        """ RSE (CLIENTS): add a protocol with insufficient parameters (InvalidObject)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        try:
            self.client.add_protocol(protocol_rse,
                                     {'hostname': 'localhost',
                                      'scheme': 'MOCK_Fail',
                                      'port': 17,
                                      'prefix': '/the/one/with/all/the/files',
                                      # 'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'domains': {
                                          'lan': {'read': 1,
                                                  'write': 1,
                                                  'delete': 1}},
                                      'extended_attributes': 'TheOneWithAllTheRest'})

            self.client.delete_protocols(protocol_rse, 'Mock_Insuff_Params')
            self.client.delete_rse(protocol_rse)
        except:  # explicity raise the correct Exception for MySQL
            raise InvalidObject

    @raises(Duplicate)
    def test_add_protocol_duplicate(self):
        """ RSE (CLIENTS): add duplicate protocol to rse (Duplicate)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        for i in range(2):
            try:
                self.client.add_protocol(protocol_rse,
                                         {'hostname': 'localhost',
                                          'scheme': 'MOCK_Duplicate',
                                          'port': 17,
                                          'prefix': '/the/one/with/all/the/files',
                                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                          'domains': {
                                              'lan': {'read': 1,
                                                      'write': 1,
                                                      'delete': 1}},
                                          'extended_attributes': 'TheOneWithAllTheRest'})
            except Exception, e:
                self.client.delete_protocols(protocol_rse, 'MOCK_Duplicate')
                self.client.delete_rse(protocol_rse)
                raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_Duplicate')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolDomainNotSupported)
    def test_add_protocol_not_suppotred_domain(self):
        """ RSE (CLIENTS): add a protocol with unsupported domain parameters (RSEProtocolDomainNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        self.client.add_protocol(protocol_rse,
                                 {'hostname': 'localhost',
                                  'scheme': 'Mock_Insuff_Params',
                                  'port': 17,
                                  'prefix': '/the/one/with/all/the/files',
                                  # 'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'domains': {
                                      'FIRENDS': {'read': 1,
                                                  'write': 1,
                                                  'delete': 1}},
                                  'extended_attributes': 'TheOneWithAllTheRest'})
        self.client.delete_protocols(protocol_rse, 'Mock_Insuff_Params')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolPriorityError)
    def test_add_protocol_wrong_priority(self):
        """ RSE (CLIENTS): Add a protocol with an invalid priority for ranking. """
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
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
            self.client.add_protocol(protocol_rse,
                                     {'hostname': 'localhost',
                                      'scheme': 'MOCK',
                                      'port': 815,
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'domains': {
                                          'lan': {'read': 4,
                                                  'write': 99,
                                                  'delete': -1}},
                                      'extended_attributes': 'TheOneWithAllTheRest'})
        except RSEProtocolPriorityError:
            self.client.delete_protocols(protocol_rse, scheme='MOCK')
            self.client.delete_rse(protocol_rse)
            raise
        self.client.delete_protocols(protocol_rse, scheme='MOCK')
        self.client.delete_rse(protocol_rse)

    # DELETE PROTOCOLS

    @raises(RSENotFound)
    def test_del_protocol_rse_not_found(self):
        """ RSE (CLIENTS): delete a protocol from an rse that does not exist (RSENotFound)."""
        self.client.delete_protocols('The One that shouldn\'t be here', 'MOCK_Fail')

    def test_del_protocol_id(self):
        """ RSE (CLIENTS): delete multiple protocols with the same identifier from an rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_ID_SUCCESS'
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     {'hostname': 'localhost',
                                      'scheme': protocol_id,
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'domains': {
                                          'lan': {'read': 1,
                                                  'write': 1,
                                                  'delete': 1}}})
        self.client.delete_protocols(protocol_rse, protocol_id)

        # check if empty
        resp = None
        try:
            resp = mgr.get_rse_info(protocol_rse)
            mgr.select_protocol(resp, 'read', scheme=protocol_id)
        except RSEProtocolNotSupported:
            self.client.delete_rse(protocol_rse)
            return

        self.client.delete_protocols(protocol_rse, protocol_id)
        self.client.delete_rse(protocol_rse)
        raise Exception('Protocols not deleted. Remaining: %s' % resp)

    @raises(RSEProtocolNotSupported)
    def test_del_protocol_id_protocol_not_supported(self):
        """ RSE (CLIENTS): delete a none-existing protocol from an rse (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        try:
            self.client.delete_protocols(protocol_rse, 'MOCK_Fail')
        except Exception, e:
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_rse(protocol_rse)

    def test_del_protocol_hostname(self):
        """ RSE (CLIENTS): delete multiple protocols with the same identifier, and the same hostname from an rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_HOST_SUCCESS'
        protocol_hostname = ['localhost', 'an_other_host', 'localhost']
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     {'hostname': protocol_hostname[i],
                                      'scheme': protocol_id,
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'domains': {
                                          'lan': {'read': 1,
                                                  'write': 1,
                                                  'delete': 1}},
                                      'extended_attributes': 'TheOneWithAllTheRest'})
        self.client.delete_protocols(protocol_rse, scheme=protocol_id, hostname='localhost')

        # check if protocol for 'other_host' are still there
        resp = mgr.get_rse_info(protocol_rse)
        for r in resp['protocols']:
            if r['hostname'] == 'localhost':
                self.client.delete_rse(protocol_rse)
                raise Exception('Protocols not deleted. Remaining: %s' % resp)

        self.client.delete_protocols(protocol_rse, scheme=protocol_id, hostname='an_other_host')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolNotSupported)
    def test_del_protocol_hostname_protocol_not_supported(self):
        """ RSE (CLIENTS): delete a none-existing protocol from an rse with given hostname (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        protocol_id = 'MOCK_PROTOCOL_DEL_HOST_FAIL'
        self.client.add_rse(protocol_rse)
        self.client.add_protocol(protocol_rse,
                                 {'hostname': 'localhost',
                                  'scheme': protocol_id,
                                  'port': 42,
                                  'prefix': '/the/one/with/all/the/files',
                                  'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'domains': {
                                      'lan': {'read': 1,
                                              'write': 1,
                                              'delete': 1}},
                                  'extended_attributes': 'TheOneWithAllTheRest'})
        try:
            self.client.delete_protocols(protocol_rse, 'MOCK_Fail', hostname='an_other_host')
        except Exception, e:
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_Fail', hostname='localhost')
        self.client.delete_rse(protocol_rse)

    def test_del_protocol_port(self):
        """ RSE (CLIENTS): delete a specific protocol from an rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_PORT_SUCCESS'
        protocol_hostname = ['localhost', 'an_other_host', 'localhost']
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     {'hostname': protocol_hostname[i],
                                      'scheme': protocol_id,
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'domains': {
                                          'lan': {'read': 1,
                                                  'write': 1,
                                                  'delete': 1}},
                                      'extended_attributes': 'TheOneWithAllTheRest'})
        self.client.delete_protocols(protocol_rse, scheme=protocol_id, hostname='localhost', port=17)

        # check remaining protocols
        resp = mgr.get_rse_info(protocol_rse)
        for r in resp['protocols']:
            if r['port'] == 17:
                self.client.delete_rse(protocol_rse, protocol_id)
                self.client.delete_rse(protocol_rse)
                raise Exception('Protocols not deleted. Remaining: %s' % resp)
        self.client.delete_protocols(protocol_rse, protocol_id)
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolNotSupported)
    def test_del_protocol_port_protocol_not_supported(self):
        """ RSE (CLIENTS): delete a specific protocol from an rse. (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        protocol_id = 'MOCK_PROTOCOL_DEL_PORT_FAIL'
        self.client.add_rse(protocol_rse)
        self.client.add_protocol(protocol_rse,
                                 {'hostname': 'localhost',
                                  'scheme': protocol_id,
                                  'port': 42,
                                  'prefix': '/the/one/with/all/the/files',
                                  'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'domains': {
                                      'lan': {'read': 1,
                                              'write': 1,
                                              'delete': 1}},
                                  'extended_attributes': 'TheOneWithAllTheRest'})
        try:
            self.client.delete_protocols(protocol_rse, 'MOCK_Fail', hostname='localhost', port=17)
        except Exception, e:
            self.client.delete_protocols(protocol_rse, protocol_id)
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, protocol_id)
        self.client.delete_rse(protocol_rse)

    # GET PROTOCOLS

    def test_get_protocols(self):
        """ RSE (CLIENTS): get protocols of rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_READ',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1},
                          'wan': {'read': 0,
                                  'write': 0,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1},
                          'wan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 0,
                                  'delete': 1},
                          'wan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)
        # GET all = 3
        resp = mgr.get_rse_info(protocol_rse)
        if len(resp['protocols']) != 3:
            for p in protocols:
                self.client.delete_protocols(protocol_rse, p['scheme'])
            self.client.delete_rse(protocol_rse)
            raise Exception('Unexpected protocols returned: %s' % resp)
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['scheme'])
        self.client.delete_rse(protocol_rse)

    @raises(RSENotFound)
    def test_get_protocols_rse_not_found(self):
        """ RSE (CLIENTS): get all protocols of rse (RSENotFound)."""
        mgr.get_rse_info("TheOnethatshouldnotbehere")

    def test_get_protocols_operations(self):
        """ RSE (CLIENTS): get protocols for operations of rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
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
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 0,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol identifier include supported operations
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        ops = {'read': 1, 'write': 2, 'delete': 3}
        rse_attr = mgr.get_rse_info(protocol_rse)
        rse_attr['domain'] = ['lan']
        for op in ops:
            # resp = self.client.get_protocols(protocol_rse, operation=op, protocol_domain='lan')
            p = mgr.select_protocol(rse_attr, op)
            if op not in p['scheme'].lower():
                for p in protocols:
                    self.client.delete_protocols(protocol_rse, p['scheme'])
                self.client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, p))
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['scheme'])
        self.client.delete_rse(protocol_rse)

    def test_get_protocols_defaults(self):
        """ RSE (CLIENTS): get default protocols for operations of rse."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
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
            self.client.add_protocol(protocol_rse, p)

        rse_attr = mgr.get_rse_info(protocol_rse)
        rse_attr['domain'] = ['lan']
        for op in ['delete', 'read', 'write']:
            # resp = self.client.get_protocols(protocol_rse, operation=op, default=True, protocol_domain='lan')
            p = mgr.select_protocol(rse_attr, op)
            print p['scheme']
            print op
            if op not in p['scheme'].lower():
                for p in protocols:
                    self.client.delete_protocols(protocol_rse, p['scheme'])
                self.client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, p))
        rse_attr['domain'] = ['wan']
        for op in ['delete', 'read', 'write']:
            # resp = self.client.get_protocols(protocol_rse, operation=op, default=True, protocol_domain='wan')
            p = mgr.select_protocol(rse_attr, op)
            if ((op == 'delete') and (p['port'] != 17)) or ((op == 'read') and (p['port'] != 42)) or ((op == 'write') and (p['port'] != 19)):
                for p in protocols:
                    self.client.delete_protocols(protocol_rse, p['scheme'])
                self.client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, p))
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['scheme'])
        self.client.delete_rse(protocol_rse)

    def test_get_protocols_nested_attributes(self):
        """ RSE (CLIENTS): get nested extended_attributes."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
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
            self.client.add_protocol(protocol_rse, p)

        resp = mgr.get_rse_info(protocol_rse)['protocols']
        assert((not resp[0]['extended_attributes']['more']['value2']) and resp[0]['extended_attributes']['more']['value1'])

    @raises(RSEProtocolNotSupported)
    def test_get_protocols_operations_not_supported(self):
        """ RSE (CLIENTS): get protocols for operations of rse (RSEOperationNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 0,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(protocol_rse)
            rse_attr['domain'] = ['lan']
            mgr.select_protocol(rse_attr, 'read')
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
            self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
        self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolDomainNotSupported)
    def test_get_protocols_domain_not_exist(self):
        """ RSE (CLIENTS): get protocols for operations of rse in not existing domain (RSEProtocolDomainNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(protocol_rse)
            rse_attr['domain'] = ['FRIENDS']
            mgr.select_protocol(rse_attr, 'write')
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolNotSupported)
    def test_get_protocols_domain_not_supported(self):
        """ RSE (CLIENTS): get protocols for operations of rse in unsupported domain (RSEOperationNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(protocol_rse)
            rse_attr['domain'] = ['wan']
            mgr.select_protocol(rse_attr, 'write')
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolNotSupported)
    def test_get_protocols_defaults_not_supported(self):
        """ RSE (CLIENTS): get default protocols for operations of rse (RSEOperationNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 0,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        # Protocol for read is undefined
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        try:
            rse_attr = mgr.get_rse_info(protocol_rse)
            rse_attr['domain'] = ['lan']
            mgr.select_protocol(rse_attr, 'read')
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
            self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
        self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
        self.client.delete_rse(protocol_rse)

    # UPDATE PROTOCOLS

    @raises(Duplicate)
    def test_update_protocols_port_exist(self):
        """ RSE (CLIENTS): set new values for various protocol attributes."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 11,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'}]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        try:
            self.client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=17, data={'prefix': 'where/the/files/are', 'extended_attributes': 'Something else', 'port': '11'})
        except Exception as e:
            self.client.delete_protocols(protocol_rse, 'MOCK')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK')
        self.client.delete_rse(protocol_rse)

    def test_update_protocols_various_attributes(self):
        """ RSE (CLIENTS): set new values for various protocol attributes."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'}]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        self.client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=17, data={'prefix': 'where/the/files/are', 'extended_attributes': 'Something else', 'port': '12'})
        rse_attr = mgr.get_rse_info(protocol_rse)
        rse_attr['domain'] = ['lan']
        p = mgr.select_protocol(rse_attr, 'read', scheme='MOCK')
        if p['prefix'] != 'where/the/files/are' and p['extended_attributes'] != 'Something else':
            raise Exception('Update gave unexpected results: %s' % p)
        self.client.delete_protocols(protocol_rse, 'MOCK')
        self.client.delete_rse(protocol_rse)

    def test_swap_protocol(self):
        """ RSE (CLIENTS): swaps the priority of two protocols by scheme. """
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCKA',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCKB',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 2,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCKC',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 3,
                                  'write': 0,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        self.client.swap_protocols(protocol_rse, 'lan', 'read', 'MOCKA', 'MOCKC')
        prots = self.client.get_protocols(protocol_rse)
        for p in prots:
            if p['scheme'] == 'MOCKA':
                if p['domains']['lan']['read'] != 3:
                    print 'MOCKA with unexpected priority'
                    print prots
                    assert(False)
            if p['scheme'] == 'MOCKC':
                if p['domains']['lan']['read'] != 1:
                    print 'MOCKC with unexpected priority'
                    print prots
                    assert(False)
        assert(True)

    @raises(RSENotFound)
    def test_update_protocols_rse_not_found(self):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse (RSENotFound)."""
        self.client.update_protocols('The One that shouldn\'t be here', scheme='MOCK_Fail', hostname='localhost', port=17, data={'prefix': 'where/the/files/are'})

    @raises(RSEProtocolNotSupported)
    def test_update_protocols_not_supported(self):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse (RSEProtocolNotSupported)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 1,
                                  'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'},
                     {'scheme': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {
                          'lan': {'read': 0,
                                  'write': 0,
                                  'delete': 1}},
                      'extended_attributes': 'TheOneWithAllTheRest'}, ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p)

        try:
            self.client.update_protocols(protocol_rse, scheme='MOCK_UNDEFINED', hostname='localhost', port=17, data={'delete_lan': 1})
        except Exception, e:
            for p in protocols:
                self.client.delete_protocols(protocol_rse, p['scheme'])
            self.client.delete_rse(protocol_rse)
            raise e
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['scheme'])
        self.client.delete_rse(protocol_rse)

    @raises(InvalidObject)
    def test_update_protocols_invalid_value(self):
        """ RSE (CLIENTS): update all protocol with invalid value (InvalidObject)."""
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      # 'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'domains': {'lan': {'read': 1,
                                          'write': 1,
                                          'delete': 0}},
                      'extended_attributes': 'TheOneWithAllTheRest'}]

        try:
            for p in protocols:
                self.client.add_protocol(protocol_rse, p)
                self.client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=17, data={'impl': None})
        except:
            raise InvalidObject  # explicity raise the correct Exception for MySQL
        finally:
            try:
                self.client.delete_protocols(protocol_rse, 'MOCK')
            except:
                pass  # for MySQL
            finally:
                self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolPriorityError)
    def test_update_protocol_wrong_priority(self):
        """  RSE (CLIENTS): Add a protocol with an invalid priority for ranking. """
        protocol_rse = rse_name_generator()
        self.client.add_rse(protocol_rse)
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
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
            self.client.update_protocols(protocol_rse, scheme='MOCK', hostname='localhost', port=42, data={'domains': {'lan': {'read': 4}}})
        except RSEProtocolPriorityError:
            self.client.delete_protocols(protocol_rse, scheme='MOCK')
            self.client.delete_rse(protocol_rse)
            raise
        self.client.delete_protocols(protocol_rse, scheme='MOCK')
        self.client.delete_rse(protocol_rse)

    def test_set_rse_usage(self):
        """ RSE (CLIENTS): Test the update of RSE usage."""
        assert_equal(self.client.set_rse_usage(rse='MOCK', source='srm', used=999200L, free=800L), True)
        usages = self.client.get_rse_usage(rse='MOCK')
        for usage in usages:
            if usage['source'] == 'srm':
                assert_equal(usage['total'], 1000000)
        assert_equal(self.client.set_rse_usage(rse='MOCK', source='srm', used=999920L, free=80L), True)
        for usage in self.client.list_rse_usage_history(rse='MOCK'):
            assert_equal(usage['free'], 80)
            break

    def test_set_rse_limits(self):
        """ RSE (CLIENTS): Test the update of RSE limits."""
        assert_equal(self.client.set_rse_limits(rse='MOCK', name='MinFreeSpace', value=1000000L), True)
        limits = self.client.get_rse_limits(rse='MOCK')
        assert_equal(limits['MinFreeSpace'], 1000000)
