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

import pytest

from rucio.common.exception import RuleNotFound, UnsupportedOperation
from rucio.core.account_limit import set_local_account_limit
from rucio.core import config as config_core
from rucio.core.did import attach_dids, set_status, set_metadata
from rucio.core.lock import successful_transfer
from rucio.core.replica import add_replicas
from rucio.core.rse import add_rse_attribute, fill_rse_expired, get_rse_usage, set_rse_usage
from rucio.core.rule import add_rule, get_rule, delete_rule, update_rule
from rucio.core.rse_expression_parser import REGION
from rucio.daemons.abacus.rse import run as run_abacus
from rucio.daemons.bb8.common import rebalance_rule
from rucio.daemons.bb8.bb8 import run as bb8_run
from rucio.daemons.judge.cleaner import rule_cleaner
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.daemons.undertaker import undertaker
from rucio.db.sqla.constants import RuleState
from rucio.tests.test_rule import create_files, tag_generator


@pytest.mark.noparallel(reason='uses daemons')
def test_bb8_rebalance_rule(vo, root_account, jdoe_account, rse_factory, mock_scope, did_factory):
    """BB8: Test the rebalance rule method"""
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()

    # Add Tags
    T1 = tag_generator()
    T2 = tag_generator()
    add_rse_attribute(rse1_id, T1, True)
    add_rse_attribute(rse2_id, T2, True)

    # Add fake weights
    add_rse_attribute(rse1_id, "fakeweight", 10)
    add_rse_attribute(rse2_id, "fakeweight", 0)

    # Add quota
    set_local_account_limit(jdoe_account, rse1_id, -1)
    set_local_account_limit(jdoe_account, rse2_id, -1)

    set_local_account_limit(root_account, rse1_id, -1)
    set_local_account_limit(root_account, rse2_id, -1)

    files = create_files(3, mock_scope, rse1_id)
    dataset = did_factory.make_dataset()
    attach_dids(mock_scope, dataset['name'], files, jdoe_account)
    set_status(mock_scope, dataset['name'], open=False)

    # Invalid the cache because the result of parse_expression is cached
    REGION.invalidate()

    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dataset['name']}], account=jdoe_account, copies=1, rse_expression=rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
    rule = {}
    try:
        rule = get_rule(rule_id)
    except:
        pytest.raises(RuleNotFound, get_rule, rule_id)
    child_rule = rebalance_rule(rule, 'Rebalance', rse2, priority=3)

    rule_cleaner(once=True)

    assert(get_rule(rule_id)['expires_at'] <= datetime.utcnow())
    assert(get_rule(rule_id)['child_rule_id'] == child_rule)

    rule_cleaner(once=True)

    assert(get_rule(rule_id)['expires_at'] <= datetime.utcnow())

    successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=rse2_id, nowait=False)
    successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=rse2_id, nowait=False)
    with pytest.raises(UnsupportedOperation):
        delete_rule(rule_id)
    successful_transfer(scope=mock_scope, name=files[2]['name'], rse_id=rse2_id, nowait=False)

    rule_cleaner(once=True)
    assert(get_rule(child_rule)['state'] == RuleState.OK)
    set_metadata(mock_scope, dataset['name'], 'lifetime', -86400)
    undertaker.run(once=True)


@pytest.mark.noparallel(reason='uses daemons')
def test_bb8_full_workflow(vo, root_account, jdoe_account, rse_factory, mock_scope, did_factory):
    """BB8: Test the rebalance rule method"""
    config_core.set(section='bb8', option='allowed_accounts', value='jdoe')
    tot_rses = 4
    rses = [rse_factory.make_posix_rse() for _ in range(tot_rses)]
    rse1, rse1_id = rses[0]
    rse2, rse2_id = rses[1]
    rse3, rse3_id = rses[2]
    rse4, rse4_id = rses[3]

    # Add Tags
    # RSE 1 and 2 nmatch expression T1=true
    # RSE 3 and 4 nmatch expression T2=true
    T1 = tag_generator()
    T2 = tag_generator()
    add_rse_attribute(rse1_id, T1, True)
    add_rse_attribute(rse2_id, T1, True)
    add_rse_attribute(rse3_id, T2, True)
    add_rse_attribute(rse4_id, T2, True)

    # Add fake weights
    add_rse_attribute(rse1_id, "fakeweight", 10)
    add_rse_attribute(rse2_id, "fakeweight", 0)
    add_rse_attribute(rse3_id, "fakeweight", 0)
    add_rse_attribute(rse4_id, "fakeweight", 0)
    add_rse_attribute(rse1_id, "freespace", 1)
    add_rse_attribute(rse2_id, "freespace", 1)
    add_rse_attribute(rse3_id, "freespace", 1)
    add_rse_attribute(rse4_id, "freespace", 1)

    # Add quota
    set_local_account_limit(jdoe_account, rse1_id, -1)
    set_local_account_limit(jdoe_account, rse2_id, -1)
    set_local_account_limit(jdoe_account, rse3_id, -1)
    set_local_account_limit(jdoe_account, rse4_id, -1)

    set_local_account_limit(root_account, rse1_id, -1)
    set_local_account_limit(root_account, rse2_id, -1)
    set_local_account_limit(root_account, rse3_id, -1)
    set_local_account_limit(root_account, rse4_id, -1)

    # Invalid the cache because the result of parse_expression is cached
    REGION.invalidate()

    tot_datasets = 4
    # Create a list of datasets
    datasets = [did_factory.make_dataset() for _ in range(tot_datasets)]
    dsn = [dataset['name'] for dataset in datasets]

    rules = list()

    base_unit = 100000000000
    nb_files1 = 7
    nb_files2 = 5
    nb_files3 = 3
    nb_files4 = 2
    file_size = 1 * base_unit
    rule_to_rebalance = None

    # Add one secondary file
    files = create_files(1, mock_scope, rse1_id, bytes_=1)
    add_rule(dids=[{'scope': mock_scope, 'name': files[0]['name']}], account=jdoe_account, copies=1, rse_expression=rse1, grouping='DATASET', weight=None, lifetime=-86400, locked=False, subscription_id=None)[0]
    for cnt in range(3, tot_rses):
        add_replicas(rses[cnt][1], files, jdoe_account)
        add_rule(dids=[{'scope': mock_scope, 'name': files[0]['name']}], account=jdoe_account, copies=1, rse_expression=rses[cnt][0], grouping='DATASET', weight=None, lifetime=-86400, locked=False, subscription_id=None)[0]
    rule_cleaner(once=True)

    # Create dataset 1 of 800 GB and create a rule on RSE 1 and RSE 3
    files = create_files(nb_files1, mock_scope, rse1_id, bytes_=file_size)
    attach_dids(mock_scope, dsn[0], files, jdoe_account)

    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[0]}], account=jdoe_account, copies=1, rse_expression=rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    rules.append(rule_id)

    add_replicas(rse3_id, files, jdoe_account)
    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[0]}], account=jdoe_account, copies=1, rse_expression=rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    rules.append(rule_id)

    # Create dataset 2 of 500 GB and create a rule on RSE 1 and RSE 2
    files = create_files(nb_files2, mock_scope, rse1_id, bytes_=file_size)
    attach_dids(mock_scope, dsn[1], files, jdoe_account)

    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[1]}], account=jdoe_account, copies=1, rse_expression=rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    rules.append(rule_id)

    add_replicas(rse2_id, files, jdoe_account)
    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[1]}], account=jdoe_account, copies=1, rse_expression=rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    rules.append(rule_id)

    # Create dataset 3 of 300 GB and create a rule on RSE 1. The copy on RSE 3 is secondary
    files = create_files(nb_files3, mock_scope, rse1_id, bytes_=file_size)
    attach_dids(mock_scope, dsn[2], files, jdoe_account)

    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[2]}], account=jdoe_account, copies=1, rse_expression=rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    rule_to_rebalance = rule_id
    rules.append(rule_id)

    add_replicas(rse3_id, files, jdoe_account)
    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[2]}], account=jdoe_account, copies=1, rse_expression=rse3, grouping='DATASET', weight=None, lifetime=-86400, locked=False, subscription_id=None)[0]
    rule_cleaner(once=True)
    try:
        rule = get_rule(rule_id)
    except:
        pytest.raises(RuleNotFound, get_rule, rule_id)

    # Create dataset 4 of 200 GB and create a rule on RSE 3. The copy on RSE 2 is secondary
    files = create_files(nb_files4, mock_scope, rse3_id, bytes_=file_size)
    attach_dids(mock_scope, dsn[3], files, jdoe_account)

    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[3]}], account=jdoe_account, copies=1, rse_expression=rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    rules.append(rule_id)

    add_replicas(rse2_id, files, jdoe_account)
    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dsn[3]}], account=jdoe_account, copies=1, rse_expression=rse2, grouping='DATASET', weight=None, lifetime=-86400, locked=False, subscription_id=None)[0]
    rule_cleaner(once=True)
    try:
        rule = get_rule(rule_id)
    except:
        pytest.raises(RuleNotFound, get_rule, rule_id)

    for dataset in dsn:
        set_status(mock_scope, dataset, open=False)

    for rse in rses:
        fill_rse_expired(rse[1])
        set_rse_usage(rse_id=rse[1], source='min_free_space', used=2 * base_unit, free=2 * base_unit, session=None)
        set_rse_usage(rse_id=rse[1], source='storage', used=15 * base_unit, free=2 * base_unit, session=None)
    set_rse_usage(rse_id=rse2_id, source='min_free_space', used=1 * base_unit, free=1 * base_unit, session=None)
    set_rse_usage(rse_id=rse2_id, source='storage', used=6 * base_unit, free=5 * base_unit, session=None)

    run_abacus(once=True, threads=1, fill_history_table=False, sleep_time=10)
    # Summary :
    # RSE 1 : 1500 GB primary + 1 B secondary
    tot_space = [src for src in get_rse_usage(rse1_id) if src['source'] == 'rucio'][0]
    expired = [src for src in get_rse_usage(rse1_id) if src['source'] == 'expired'][0]
    assert tot_space['used'] == (nb_files1 + nb_files2 + nb_files3) * file_size + 1
    assert expired['used'] == 1
    # RSE 2 : 500 GB primary + 100 GB secondary
    tot_space = [src for src in get_rse_usage(rse2_id) if src['source'] == 'rucio'][0]
    expired = [src for src in get_rse_usage(rse2_id) if src['source'] == 'expired'][0]
    assert tot_space['used'] == (nb_files2 + nb_files4) * file_size
    assert expired['used'] == nb_files4 * file_size
    # Total primary on T1=true : 2000 GB
    # Total secondary on T1=true : 200 GB
    # Ratio secondary / primary = 10  %
    # Ratio on RSE 1 : 0 %
    # Ratio on RSE 2 : 40 %

    # Now run BB8

    re_evaluator(once=True, sleep_time=30, did_limit=100)
    bb8_run(once=True, rse_expression='%s=true' % str(T1), move_subscriptions=False, use_dump=False, sleep_time=300, threads=1, dry_run=False)

    for rule_id in rules:
        rule = get_rule(rule_id)
        if rule_id != rule_to_rebalance:
            assert(rule['child_rule_id'] is None)
        else:
            assert(rule['child_rule_id'] is not None)
            assert(rule['expires_at'] <= datetime.utcnow() + timedelta(seconds=1))  # timedelta needed to prevent failure due to rounding effects
            child_rule_id = rule['child_rule_id']
            child_rule = get_rule(child_rule_id)
            assert(child_rule['rse_expression'] == rse2)
            # For teardown, delete child rule
            update_rule(child_rule_id, {'lifetime': -86400})
    rule_cleaner(once=True)

    for dataset in dsn:
        set_metadata(mock_scope, dataset, 'lifetime', -86400)
    undertaker.run(once=True)
