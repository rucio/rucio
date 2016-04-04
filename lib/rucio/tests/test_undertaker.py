# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2015

from datetime import datetime, timedelta

from nose.tools import assert_not_equal

from rucio.common.utils import generate_uuid
from rucio.core.account_limit import set_account_limit
from rucio.core.did import add_dids, attach_dids, list_expired_dids
from rucio.core.replica import get_replica
from rucio.core.rule import add_rules
from rucio.core.rse import get_rse_id
from rucio.daemons.undertaker import undertaker


class TestUndertaker:

    def test_undertaker(self):
        """ UNDERTAKER (CORE): Test the undertaker. """
        tmp_scope = 'mock'
        nbdatasets = 5
        nbfiles = 5

        set_account_limit('jdoe', get_rse_id('MOCK'), -1)

        dsns1 = [{'name': 'dsn_%s' % generate_uuid(),
                  'scope': tmp_scope,
                  'type': 'DATASET',
                  'lifetime': -1} for i in xrange(nbdatasets)]

        dsns2 = [{'name': 'dsn_%s' % generate_uuid(),
                  'scope': tmp_scope,
                  'type': 'DATASET',
                  'lifetime': -1,
                  'rules': [{'account': 'jdoe', 'copies': 1,
                             'rse_expression': 'MOCK',
                             'grouping': 'DATASET'}]} for i in xrange(nbdatasets)]

        add_dids(dids=dsns1 + dsns2, account='root')

        replicas = list()
        for dsn in dsns1 + dsns2:
            files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'tombstone': datetime.utcnow() + timedelta(weeks=2), 'meta': {'events': 10}} for i in xrange(nbfiles)]
            attach_dids(scope=tmp_scope, name=dsn['name'], rse='MOCK', dids=files, account='root')
            replicas += files

        add_rules(dids=dsns1, rules=[{'account': 'jdoe', 'copies': 1, 'rse_expression': 'MOCK', 'grouping': 'DATASET'}])

        undertaker(worker_number=1, total_workers=1, once=True)
        undertaker(worker_number=1, total_workers=1, once=True)

        for replica in replicas:
            assert_not_equal(get_replica(scope=replica['scope'], name=replica['name'], rse='MOCK')['tombstone'], None)

    def test_list_expired_dids_with_locked_rules(self):
        """ UNDERTAKER (CORE): Test that the undertaker does not list expired dids with locked rules"""
        tmp_scope = 'mock'

        # Add quota
        set_account_limit('jdoe', get_rse_id('MOCK'), -1)

        dsn = {'name': 'dsn_%s' % generate_uuid(),
               'scope': tmp_scope,
               'type': 'DATASET',
               'lifetime': -1,
               'rules': [{'account': 'jdoe', 'copies': 1,
                          'rse_expression': 'MOCK', 'locked': True,
                          'grouping': 'DATASET'}]}

        add_dids(dids=[dsn], account='root')

        for did in list_expired_dids(limit=1000):
            assert(did['scope'] != dsn['scope'] and did['name'] != dsn['name'])
