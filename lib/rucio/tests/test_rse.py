# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from json import dumps, loads
from nose.tools import raises, assert_equal, assert_true, assert_in, assert_raises
from paste.fixture import TestApp
from random import randint

from rucio.client.rseclient import RSEClient
from rucio.common.exception import Duplicate, RSENotFound, RSEProtocolNotSupported, RSEOperationNotSupported, InvalidObject
from rucio.common.utils import generate_uuid as uuid
from rucio.core.rse import add_rse, del_rse, list_rses,\
    rse_exists, set_rse_usage, get_rse_usage, add_rse_attribute
from rucio.web.rest.rse import app as rse_app
from rucio.web.rest.authentication import app as auth_app


class TestRSECoreApi():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_check_for_rse(self):
        """ RSE (CORE): Test the creation, query, and deletion of a RSE """
        rse = 'MOCK_' + str(uuid())
        invalid_rse = 'BLAHBLAH'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(rse_exists(invalid_rse), False)
        del_rse(rse)

    @raises(Duplicate)
    def test_create_and_create_for_rse(self):
        """ RSE (CORE): Test the double creation of the same RSE """
        rse = 'MOCK_' + str(uuid())
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse(rse)

    def test_list_rses(self):
        """ RSE (CORE): Test the listing of all RSEs """
        rse = u'MOCK_' + str(uuid())
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse_attribute(rse=rse, key='tier', value='1')
        rses = list_rses(filters={'tier': '1'})
        assert_in(rse, rses)
        del_rse(rse)

    def test_list_rses2(self):
        """ RSE (CORE): Test the listing of all RSEs with multiple filters"""
        rse = u'MOCK_' + str(uuid())
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        add_rse_attribute(rse=rse, key='tier', value='1')
        add_rse_attribute(rse=rse, key='country', value='us')
        rses = list_rses(filters={'tier': '1', 'country': 'us'})
        assert_in(rse, rses)
        del_rse(rse)

    def test_set_rse_usage(self):
        """ RSE (CORE): Test the update of RSE usage """
        rse = 'MOCK_' + str(uuid())
        source = 'srm'
        add_rse(rse)
        assert_equal(rse_exists(rse), True)
        assert_equal(set_rse_usage(rse=rse, source=source, total=1000000L, free=80L), True)
        usage = get_rse_usage(rse=rse)
        for u in usage:
            assert_equal(u['total'], 1000000)


class TestRSE():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_rse_success(self):
        """ RSE (REST): send a POST to create a new RSE """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))
        rse = 'MOCK_' + str(uuid())

        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r3 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers3, expect_errors=True)
        assert_equal(r3.status, 409)

    def test_list_rses(self):
        """ RSE (REST): send a GET to list all rses """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))
        rse = 'MOCK_' + str(uuid())

        headers2 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r2 = TestApp(rse_app.wsgifunc(*mw)).post('/' + rse, headers=headers2, expect_errors=True)
        assert_equal(r2.status, 201)

        headers3 = {'X-Rucio-Type': 'user', 'X-Rucio-Account': 'root', 'X-Rucio-Auth-Token': str(token)}
        r3 = TestApp(rse_app.wsgifunc(*mw)).get('/', headers=headers3, expect_errors=True)
        assert_in(rse, loads(r3.body))
        assert_equal(r3.status, 200)

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


class TestRSEClient():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.client = RSEClient()

    def test_add_rse(self):
        """ RSE (CLIENTS): add a new rse."""
        rse = 'MOCK_' + str(uuid())
        ret = self.client.add_rse(rse)
        assert_true(ret)

        with assert_raises(Duplicate):
            self.client.add_rse(rse)

        bad_rse = 'MOCK_$*&##@!'
        with assert_raises(InvalidObject):
            ret = self.client.add_rse(bad_rse)

    def test_list_rses(self):
        """ RSE (CLIENTS): try to list rses."""
        rse_list = ['MOCK_' + str(uuid()) + str(i) for i in xrange(5)]
        for rse in rse_list:
            self.client.add_rse(rse)

        svr_list = self.client.list_rses()

        for rse in rse_list:
            assert_in(rse, svr_list)

    # ADD PROTOCOLS

    def test_add_protocol(self):
        """ RSE (CLIENTS): add three protocols to rse."""
        protocol_rse = 'MOCK_PROTOCOL_ADD_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocol_id = ['MOCK_' + str(uuid()) + str(i) for i in xrange(3)]
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     protocol_id[i],
                                     {'hostname': 'localhost',
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'read': randint(1, 5),
                                      'write': randint(1, 5),
                                      'delete': randint(1, 5),
                                      'extended_attributes': 'TheOneWithAllTheRest'
                                      })
        for id in protocol_id:
            self.client.delete_protocols(protocol_rse, id)
        self.client.delete_rse(protocol_rse)

    @raises(RSENotFound)
    def test_add_protocol_rse_not_found(self):
        """ RSE (CLIENTS): add a protocol to an rse that does not exist (RSENotFound)."""
        self.client.add_protocol('The One that shouldn\'t be here',
                                 'MOCK_Fail',
                                 {'hostname': 'localhost',
                                  'port': 17,
                                  'prefix': '/the/one/with/all/the/files',
                                  'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'read': randint(1, 5),
                                  'write': randint(1, 5),
                                  'delete': randint(1, 5),
                                  'extended_attributes': 'TheOneWithAllTheRest'
                                  })

    @raises(InvalidObject)
    def test_add_protocol_missing_values(self):
        """ RSE (CLIENTS): add a protocol with insufficient parameters (InvalidObject)."""
        protocol_rse = 'MOCK_PROTOCOL_ADD_MISSING_VALUES' + str(uuid())
        self.client.add_rse(protocol_rse)
        self.client.add_protocol(protocol_rse,
                                 'Mock_Insuff_Params',
                                 {'hostname': 'localhost',
                                  'port': 17,
                                  'prefix': '/the/one/with/all/the/files',
                                  #'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'read': randint(1, 5),
                                  'write': randint(1, 5),
                                  'delete': randint(1, 5),
                                  'extended_attributes': 'TheOneWithAllTheRest'
                                  })
        self.client.delete_protocols(protocol_rse, 'Mock_Insuff_Params')
        self.client.delete_rse(protocol_rse)

    @raises(Duplicate)
    def test_add_protocol_duplicate(self):
        """ RSE (CLIENTS): add duplicate protocol to rse (Duplicate)."""
        protocol_rse = 'MOCK_PROTOCOL_ADD_DUPLICATE' + str(uuid())
        self.client.add_rse(protocol_rse)
        for i in range(2):
            try:
                self.client.add_protocol(protocol_rse,
                                         'MOCK_Duplicate',
                                         {'hostname': 'localhost',
                                          'port': 17,
                                          'prefix': '/the/one/with/all/the/files',
                                          'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                          'read': randint(1, 5),
                                          'write': randint(1, 5),
                                          'delete': randint(1, 5),
                                          'extended_attributes': 'TheOneWithAllTheRest'
                                          })
            except Exception, e:
                self.client.delete_protocols(protocol_rse, 'MOCK_Duplicate')
                self.client.delete_rse(protocol_rse)
                raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_Duplicate')
        self.client.delete_rse(protocol_rse)

    # DELETE PROTOCOLS

    @raises(RSENotFound)
    def test_del_protocol_rse_not_found(self):
        """ RSE (CLIENTS): delete a protocol from an rse that does not exist (RSENotFound)."""
        self.client.delete_protocols('The One that shouldn\'t be here', 'MOCK_Fail')

    def test_del_protocol_id(self):
        """ RSE (CLIENTS): delete multiple protocols with the same identifier from an rse."""
        protocol_rse = 'MOCK_PROTOCOL_DEL_ID_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_ID_SUCCESS'
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     protocol_id,
                                     {'hostname': 'localhost',
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'read': randint(1, 5),
                                      'write': randint(1, 5),
                                      'delete': randint(1, 5),
                                      })
        self.client.delete_protocols(protocol_rse, protocol_id)

        # check if empty
        resp = None
        try:
            resp = self.client.get_protocols(protocol_rse, protocol=protocol_id)
        except RSEProtocolNotSupported:
            self.client.delete_rse(protocol_rse)
            return

        self.client.delete_protocols(protocol_rse, protocol_id)
        self.client.delete_rse(protocol_rse)
        raise Exception('Protocols not deleted. Remaining: %s' % resp)

    @raises(RSEProtocolNotSupported)
    def test_del_protocol_id_protocol_not_supported(self):
        """ RSE (CLIENTS): delete a none-existing protocol from an rse (RSEProtocolNotSupported)."""
        protocol_rse = 'MOCK_PROTOCOL_DEL_ID_FAIL' + str(uuid())
        self.client.add_rse(protocol_rse)
        try:
            self.client.delete_protocols(protocol_rse, 'MOCK_Fail')
        except Exception, e:
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_rse(protocol_rse)

    def test_del_protocol_hostname(self):
        """ RSE (CLIENTS): delete multiple protocols with the same identifier, and the same hostname from an rse."""
        protocol_rse = 'MOCK_PROTOCOL_DEL_HOST_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_HOST_SUCCESS'
        protocol_hostname = ['localhost', 'an_other_host', 'localhost']
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     protocol_id,
                                     {'hostname': protocol_hostname[i],
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'read': randint(1, 5),
                                      'write': randint(1, 5),
                                      'delete': randint(1, 5),
                                      'extended_attributes': 'TheOneWithAllTheRest'
                                      })
        self.client.delete_protocols(protocol_rse, protocol=protocol_id, hostname='localhost')

        # check if protocol for 'other_host' are still there
        resp = self.client.get_protocols(protocol_rse, protocol=protocol_id)
        for r in resp:
            if r['hostname'] == 'localhost':
                self.client.delete_rse(protocol_rse)
                raise Exception('Protocols not deleted. Remaining: %s' % resp)

        self.client.delete_protocols(protocol_rse, protocol=protocol_id, hostname='an_other_host')
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolNotSupported)
    def test_del_protocol_hostname_protocol_not_supported(self):
        """ RSE (CLIENTS): delete a none-existing protocol from an rse with given hostname (RSEProtocolNotSupported)."""
        protocol_rse = 'MOCK_PROTOCOL_DEL_HOST_FAIL' + str(uuid())
        protocol_id = 'MOCK_PROTOCOL_DEL_HOST_FAIL'
        self.client.add_rse(protocol_rse)
        self.client.add_protocol(protocol_rse,
                                 protocol_id,
                                 {'hostname': 'localhost',
                                  'port': 42,
                                  'prefix': '/the/one/with/all/the/files',
                                  'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'read': randint(1, 5),
                                  'write': randint(1, 5),
                                  'delete': randint(1, 5),
                                  'extended_attributes': 'TheOneWithAllTheRest'
                                  })
        try:
            self.client.delete_protocols(protocol_rse, 'MOCK_Fail', hostname='an_other_host')
        except Exception, e:
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_Fail', hostname='localhost')
        self.client.delete_rse(protocol_rse)

    def test_del_protocol_port(self):
        """ RSE (CLIENTS): delete a specific protocol from an rse."""
        protocol_rse = 'MOCK_PROTOCOL_DEL_PORT_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocol_id = 'MOCK_DEL_PORT_SUCCESS'
        protocol_hostname = ['localhost', 'an_other_host', 'localhost']
        protocol_ports = [17, 29, 42]
        for i in range(3):
            self.client.add_protocol(protocol_rse,
                                     protocol_id,
                                     {'hostname': protocol_hostname[i],
                                      'port': protocol_ports[i],
                                      'prefix': '/the/one/with/all/the/files',
                                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                      'read': randint(1, 5),
                                      'write': randint(1, 5),
                                      'delete': randint(1, 5),
                                      'extended_attributes': 'TheOneWithAllTheRest'
                                      })
        self.client.delete_protocols(protocol_rse, protocol=protocol_id, hostname='localhost', port=17)

        # check remaining protocols
        resp = self.client.get_protocols(protocol_rse, protocol=protocol_id)
        for r in resp:
            if r['port'] == 17:
                self.client.delete_rse(protocol_rse, protocol_id)
                self.client.delete_rse(protocol_rse)
                raise Exception('Protocols not deleted. Remaining: %s' % resp)
        self.client.delete_protocols(protocol_rse, protocol_id)
        self.client.delete_rse(protocol_rse)

    @raises(RSEProtocolNotSupported)
    def test_del_protocol_port_protocol_not_supported(self):
        """ RSE (CLIENTS): delete a specific protocol from an rse. (RSEProtocolNotSupported)."""
        protocol_rse = 'MOCK_PROTOCOL_DEL_PORT_FAIL' + str(uuid())
        protocol_id = 'MOCK_PROTOCOL_DEL_PORT_FAIL'
        self.client.add_rse(protocol_rse)
        self.client.add_protocol(protocol_rse,
                                 protocol_id,
                                 {'hostname': 'localhost',
                                  'port': 42,
                                  'prefix': '/the/one/with/all/the/files',
                                  'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                                  'read': randint(1, 5),
                                  'write': randint(1, 5),
                                  'delete': randint(1, 5),
                                  'extended_attributes': 'TheOneWithAllTheRest'
                                  })
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
        protocol_rse = 'MOCK_PROTOCOL_GET_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK_READ',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': 1,
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_WRITE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': -1,
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': -1,
                      'write': -1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)
        # GET all = 3
        resp = self.client.get_protocols(protocol_rse)
        if len(resp) != 3:
            for p in protocols:
                self.client.delete_protocols(protocol_rse, p['protocol'])
            self.client.delete_rse(protocol_rse)
            raise Exception('Unexpected protocols returned: %s' % resp)
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['protocol'])
        self.client.delete_rse(protocol_rse)

    @raises(RSENotFound)
    def test_get_protocols_rse_not_found(self):
        """ RSE (CLIENTS): get all protocols of rse (RSENotFound)."""
        self.client.get_protocols('The One that shouldn\'t be here')

    def test_get_protocols_operations(self):
        """ RSE (CLIENTS): get protocols for operations of rse."""
        protocol_rse = 'MOCK_PROTOCOL_GET_OP_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK_READ_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': 1,
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': -1,
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': -1,
                      'write': -1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        # Protocol identifier include supported operations
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)

        ops = {'read': 1, 'write': 2, 'delete': 3}
        for op in ops:
            resp = self.client.get_protocols(protocol_rse, operation=op)
            for p in resp:
                if op not in p['protocol'].lower():
                    for p in protocols:
                        self.client.delete_protocols(protocol_rse, p['protocol'])
                    self.client.delete_rse(protocol_rse)
                    raise Exception('Unexpected protocols returned for %s: %s' % (op, resp))
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['protocol'])
        self.client.delete_rse(protocol_rse)

    def test_get_protocols_defaults(self):
        """ RSE (CLIENTS): get default protocols for operations of rse."""
        protocol_rse = 'MOCK_PROTOCOL_GET_DEFAULT_SUCCESS' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK_READ',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_WRITE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'write': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)

        for op in ['delete', 'read', 'write']:
            resp = self.client.get_protocols(protocol_rse, operation=op, default=True)
            if op not in resp[0]['protocol'].lower():
                for p in protocols:
                    self.client.delete_protocols(protocol_rse, p['protocol'])
                self.client.delete_rse(protocol_rse)
                raise Exception('Unexpected protocols returned for %s: %s' % (op, resp))
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['protocol'])
        self.client.delete_rse(protocol_rse)

    @raises(RSEOperationNotSupported)
    def test_get_protocols_operations_not_supported(self):
        """ RSE (CLIENTS): get protocols for operations of rse (RSEOperationNotSupported)."""
        protocol_rse = 'MOCK_PROTOCOL_GET_OP_NOT_SUPPORTED' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        # Protocol for read is undefined
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)

        try:
            self.client.get_protocols(protocol_rse, operation='read')
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
            self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
        self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
        self.client.delete_rse(protocol_rse)

    @raises(RSEOperationNotSupported)
    def test_get_protocols_defaults_not_supported(self):
        """ RSE (CLIENTS): get default protocols for operations of rse (RSEOperationNotSupported)."""
        protocol_rse = 'MOCK_PROTOCOL_GET_DEFAULT_NOT_SUPPORTED' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_WRITE_DELETE',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'write': 1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        # Protocol for read is undefined
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)

        try:
            self.client.get_protocols(protocol_rse, operation='read', default=True)
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
            self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK_WRITE_DELETE')
        self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
        self.client.delete_rse(protocol_rse)

    # UPDATE PROTOCOLS

    def test_update_protocols(self):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse."""
        protocol_rse = 'MOCK_PROTOCOL_UPDATE' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': 1,
                      'write': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'write': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)

        self.client.update_protocols(protocol_rse, protocol='MOCK', data={'prefix': 'where/the/files/are'})
        resp = self.client.get_protocols(protocol_rse, protocol='MOCK')
        for p in resp:
            if p['prefix'] != 'where/the/files/are':
                raise Exception('Update gave unexpected results: %s' % resp)
        self.client.update_protocols(protocol_rse, protocol='MOCK', hostname='localhost', port=42, data={'read': 0})
        resp = self.client.get_protocols(protocol_rse, operation='read', default=True)
        if resp[0]['port'] != 42:
            raise Exception('Update gave unexpected result for new default operation: %s' % resp)
        self.client.delete_protocols(protocol_rse, 'MOCK')
        self.client.delete_protocols(protocol_rse, 'MOCK_DELETE')
        self.client.delete_rse(protocol_rse)

    @raises(RSENotFound)
    def test_update_protocols_rse_not_found(self):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse (RSENotFound)."""
        self.client.update_protocols('The One that shouldn\'t be here', protocol='MOCK_Fail', data={'prefix': 'where/the/files/are'})

    @raises(RSEProtocolNotSupported)
    def test_update_protocols_not_supported(self):
        """ RSE (CLIENTS): update all protocols with specific identifier of rse (RSEProtocolNotSupported)."""
        protocol_rse = 'MOCK_PROTOCOL_UPDATE_NOT_SUPPORTED' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': 1,
                      'write': 1,
                      'delete': -1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK',
                      'hostname': 'localhost',
                      'port': 42,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': -1,
                      'write': 1,
                      'delete': -1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     {'protocol': 'MOCK_DELETE',
                      'hostname': 'localhost',
                      'port': 19,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': -1,
                      'write': -1,
                      'delete': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      },
                     ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)

        try:
            self.client.update_protocols(protocol_rse, protocol='MOCK_UNDEFINED', data={'delete': 1})
        except Exception, e:
            for p in protocols:
                self.client.delete_protocols(protocol_rse, p['protocol'])
            self.client.delete_rse(protocol_rse)
            raise e
        for p in protocols:
            self.client.delete_protocols(protocol_rse, p['protocol'])
        self.client.delete_rse(protocol_rse)

    @raises(InvalidObject)
    def test_update_protocols_invalid_value(self):
        """ RSE (CLIENTS): update all protocol with invalid value (InvalidObject)."""
        protocol_rse = 'MOCK_PROTOCOL_UPDATE_INVALID_VALUE' + str(uuid())
        self.client.add_rse(protocol_rse)
        protocols = [{'protocol': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/the/one/with/all/the/files',
                      'impl': 'rucio.rse.protocols.SomeProtocol.SomeImplementation',
                      'read': 1,
                      'write': 1,
                      'extended_attributes': 'TheOneWithAllTheRest'
                      }
                     ]
        for p in protocols:
            self.client.add_protocol(protocol_rse, p['protocol'], p)
        try:
            self.client.update_protocols(protocol_rse, protocol='MOCK', data={'impl': None})
        except Exception, e:
            self.client.delete_protocols(protocol_rse, 'MOCK')
            self.client.delete_rse(protocol_rse)
            raise e
        self.client.delete_protocols(protocol_rse, 'MOCK')
        self.client.delete_rse(protocol_rse)
        raise Exception('Update did not raise expected exception')
