''' Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2017
'''

from nose.tools import assert_equal

from rucio.common.utils import generate_uuid
from rucio.core.temporary_did import (add_temporary_dids, compose, delete_temporary_dids,
                                      list_expired_temporary_dids)

from rucio.client.didclient import DIDClient


def test_core_temporary_dids():
    """ TMP DATA IDENTIFIERS (CORE): """

    temporary_dids = []
    for _ in xrange(10):
        temporary_dids.append({'scope': 'mock',
                               'name': 'object_%s' % generate_uuid(),
                               'rse': 'MOCK',
                               'bytes': 1L,
                               'path': None})

    add_temporary_dids(dids=temporary_dids, account='root')

    compose(scope='mock', name='file_%s' % generate_uuid(), rse='MOCK',
            bytes=10L, sources=temporary_dids, account='root',
            md5=None, adler32=None, pfn=None, meta={}, rules=[],
            parent_scope=None, parent_name=None)

    dids = list_expired_temporary_dids(rse='MOCK', limit=10)

    rowcount = delete_temporary_dids(dids=dids)

    assert_equal(rowcount, 10)


def test_client_temporary_dids():
    """ TMP DATA IDENTIFIERS (CLIENT): """
    client = DIDClient()
    temporary_dids = []
    for _ in xrange(10):
        temporary_dids.append({'scope': 'mock',
                               'name': 'object_%s' % generate_uuid(),
                               'rse': 'MOCK',
                               'bytes': 1L,
                               'path': None})

    client.add_temporary_dids(dids=temporary_dids)
