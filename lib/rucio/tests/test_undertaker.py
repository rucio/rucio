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

from datetime import datetime, timedelta
from logging import getLogger

import pytest

from rucio.common.policy import get_policy
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_dids, attach_dids, list_expired_dids, get_did, set_metadata
from rucio.core.replica import add_replicas, get_replica
from rucio.core.rse import get_rse_id, add_rse
from rucio.core.rule import add_rules, list_rules
from rucio.daemons.judge.cleaner import rule_cleaner
from rucio.daemons.undertaker.undertaker import undertaker
from rucio.db.sqla.util import json_implemented
from rucio.tests.common import rse_name_generator, did_name_generator

LOG = getLogger(__name__)


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined rses; runs undertaker, which impacts other tests')
class TestUndertaker:

    @pytest.mark.parametrize("file_config_mock", [
        # Run test twice: with, and without, temp tables
        {"overrides": [('core', 'use_temp_tables', 'True')]},
        {"overrides": [('core', 'use_temp_tables', 'False')]},
    ], indirect=True)
    def test_undertaker(self, vo, mock_scope, root_account, file_config_mock):
        """ UNDERTAKER (CORE): Test the undertaker. """
        jdoe = InternalAccount('jdoe', vo=vo)

        nbdatasets = 5
        nbfiles = 5
        rse = 'MOCK'
        rse_id = get_rse_id('MOCK', vo=vo)

        set_local_account_limit(jdoe, rse_id, -1)

        dsns1 = [{'name': did_name_generator('dataset'),
                  'scope': mock_scope,
                  'type': 'DATASET',
                  'lifetime': -1} for _ in range(nbdatasets)]

        dsns2 = [{'name': did_name_generator('dataset'),
                  'scope': mock_scope,
                  'type': 'DATASET',
                  'lifetime': -1,
                  'rules': [{'account': jdoe, 'copies': 1,
                             'rse_expression': rse,
                             'grouping': 'DATASET'}]} for _ in range(nbdatasets)]

        add_dids(dids=dsns1 + dsns2, account=root_account)

        # arbitrary keys do not work without JSON support (sqlite, Oracle < 12)
        if json_implemented():
            # Add generic metadata on did
            set_metadata(mock_scope, dsns1[0]['name'], "test_key", "test_value")

        replicas = list()
        for dsn in dsns1 + dsns2:
            files = [{'scope': mock_scope, 'name': did_name_generator('file'),
                      'bytes': 1, 'adler32': '0cc737eb',
                      'tombstone': datetime.utcnow() + timedelta(weeks=2), 'meta': {'events': 10}} for _ in range(nbfiles)]
            attach_dids(scope=mock_scope, name=dsn['name'], rse_id=rse_id, dids=files, account=root_account)
            replicas += files

        add_rules(dids=dsns1, rules=[{'account': jdoe, 'copies': 1, 'rse_expression': rse, 'grouping': 'DATASET'}])

        undertaker(once=True)
        undertaker(once=True)

        for replica in replicas:
            assert get_replica(scope=replica['scope'], name=replica['name'], rse_id=rse_id)['tombstone'] is not None

    @pytest.mark.parametrize("file_config_mock", [
        # Run test twice: with, and without, temp tables
        {"overrides": [('core', 'use_temp_tables', 'True')]},
        {"overrides": [('core', 'use_temp_tables', 'False')]},
    ], indirect=True)
    def test_list_expired_dids_with_locked_rules(self, vo, mock_scope, root_account, file_config_mock):
        """ UNDERTAKER (CORE): Test that the undertaker does not list expired dids with locked rules"""
        jdoe = InternalAccount('jdoe', vo=vo)

        # Add quota
        set_local_account_limit(jdoe, get_rse_id('MOCK', vo=vo), -1)

        dsn = {'name': did_name_generator('dataset'),
               'scope': mock_scope,
               'type': 'DATASET',
               'lifetime': -1,
               'rules': [{'account': jdoe, 'copies': 1,
                          'rse_expression': 'MOCK', 'locked': True,
                          'grouping': 'DATASET'}]}

        add_dids(dids=[dsn], account=root_account)

        for did in list_expired_dids(limit=1000):
            assert (did['scope'], did['name']) != (dsn['scope'], dsn['name'])

    @pytest.mark.parametrize("file_config_mock", [
        # Run test twice: with, and without, temp tables
        {"overrides": [('core', 'use_temp_tables', 'True')]},
        {"overrides": [('core', 'use_temp_tables', 'False')]},
    ], indirect=True)
    def test_atlas_archival_policy(self, vo, mock_scope, root_account, file_config_mock):
        """ UNDERTAKER (CORE): Test the atlas archival policy. """
        if get_policy() != 'atlas':
            LOG.info("Skipping atlas-specific test")
            return

        jdoe = InternalAccount('jdoe', vo=vo)

        nbdatasets = 5
        nbfiles = 5

        rse = 'LOCALGROUPDISK_%s' % rse_name_generator()
        rse_id = add_rse(rse, vo=vo)

        set_local_account_limit(jdoe, rse_id, -1)

        dsns2 = [{'name': did_name_generator('dataset'),
                  'scope': mock_scope,
                  'type': 'DATASET',
                  'lifetime': -1,
                  'rules': [{'account': jdoe, 'copies': 1,
                             'rse_expression': rse,
                             'grouping': 'DATASET'}]} for _ in range(nbdatasets)]

        add_dids(dids=dsns2, account=root_account)

        replicas = list()
        for dsn in dsns2:
            files = [{'scope': mock_scope, 'name': did_name_generator('file'), 'bytes': 1,
                      'adler32': '0cc737eb', 'tombstone': datetime.utcnow() + timedelta(weeks=2), 'meta': {'events': 10}} for _ in range(nbfiles)]
            attach_dids(scope=mock_scope, name=dsn['name'], rse_id=rse_id, dids=files, account=root_account)
            replicas += files

        undertaker(once=True)

        for replica in replicas:
            assert(get_replica(scope=replica['scope'], name=replica['name'], rse_id=rse_id)['tombstone'] is None)

        for dsn in dsns2:
            assert(get_did(scope=InternalScope('archive', vo=vo), name=dsn['name'])['name'] == dsn['name'])
            assert(len([x for x in list_rules(filters={'scope': InternalScope('archive', vo=vo), 'name': dsn['name']})]) == 1)


@pytest.mark.noparallel(reason='runs undertaker, which impacts other tests')
@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('undertaker', 'purge_all_replicas', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.core.config.REGION',
]}], indirect=True)
@pytest.mark.parametrize("file_config_mock", [
    # Run test twice: with, and without, temp tables
    {"overrides": [('core', 'use_temp_tables', 'True')]},
    {"overrides": [('core', 'use_temp_tables', 'False')]},
], indirect=True)
def test_removal_all_replicas2(rse_factory, root_account, mock_scope, core_config_mock, caches_mock, file_config_mock):
    """ UNDERTAKER (CORE): Test the undertaker is setting Epoch tombstone on all the replicas. """
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()

    set_local_account_limit(root_account, rse1_id, -1)
    set_local_account_limit(root_account, rse2_id, -1)

    nbdatasets = 1
    nbfiles = 5
    dsns1 = [{'name': did_name_generator('dataset'),
              'scope': mock_scope,
              'type': 'DATASET',
              'lifetime': -1} for _ in range(nbdatasets)]

    add_dids(dids=dsns1, account=root_account)

    replicas = list()
    for dsn in dsns1:
        files = [{'scope': mock_scope,
                  'name': did_name_generator('file'),
                  'bytes': 1,
                  'adler32': '0cc737eb'} for _ in range(nbfiles)]
        attach_dids(scope=mock_scope, name=dsn['name'], rse_id=rse1_id, dids=files, account=root_account)
        add_replicas(rse_id=rse2_id, files=files, account=root_account, ignore_availability=True)
        replicas += files

    add_rules(dids=dsns1, rules=[{'account': root_account, 'copies': 1, 'rse_expression': rse1, 'grouping': 'DATASET'}])
    add_rules(dids=dsns1, rules=[{'account': root_account, 'copies': 1, 'rse_expression': rse2, 'grouping': 'DATASET', 'lifetime': -86400}])

    # Clean the rules on MOCK2. Replicas are tombstoned with non Epoch
    rule_cleaner(once=True)
    for replica in replicas:
        assert get_replica(scope=replica['scope'], name=replica['name'], rse_id=rse2_id)['tombstone'] is not None
    undertaker(once=True)
    undertaker(once=True)

    for replica in replicas:
        assert get_replica(scope=replica['scope'], name=replica['name'], rse_id=rse1_id)['tombstone'] == datetime(year=1970, month=1, day=1)
    for replica in replicas:
        assert get_replica(scope=replica['scope'], name=replica['name'], rse_id=rse2_id)['tombstone'] == datetime(year=1970, month=1, day=1)
