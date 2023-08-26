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

import os
import json

from datetime import datetime, timedelta

import pytest
from configparser import NoSectionError

from rucio.common.exception import UnsupportedOperation, ConfigNotFound
from rucio.common.policy import REGION
from rucio.common.utils import generate_uuid as uuid
from rucio.tests.common import skip_multivo
from rucio.core import config as core_config
from rucio.core.rule import add_rule, get_rule
from rucio.core.did import set_metadata, get_metadata
from rucio.core.lifetime_exception import add_exception
from rucio.daemons.atropos.atropos import atropos
from rucio.db.sqla.constants import DIDType


@skip_multivo(reason='only valid for ATLAS')
def test_lifetime_creation_core(root_account, rse_factory, mock_scope, did_factory):
    """
    Test the creation of a lifetime exception on the core side
    """
    nb_datatype = 3
    nb_datasets = 2 * nb_datatype
    yesterday = datetime.utcnow() - timedelta(days=1)
    tomorrow = datetime.utcnow() + timedelta(days=1)
    rse, rse_id = rse_factory.make_posix_rse()
    datasets = [did_factory.make_dataset() for _ in range(nb_datasets)]
    metadata = [str(uuid()) for _ in range(nb_datatype)]
    list_dids = []
    for cnt, meta in enumerate(metadata):
        dids = []
        for dataset in datasets[2 * cnt:2 * (cnt + 1)]:
            set_metadata(dataset['scope'], dataset['name'], 'datatype', meta)
            if cnt < nb_datatype - 1:
                set_metadata(dataset['scope'], dataset['name'], 'eol_at', yesterday)
            dids.append((dataset['scope'], dataset['name']))
        dids.sort()
        list_dids.append(dids)
    datasets.extend([{'scope': mock_scope, 'name': 'dataset_%s' % str(uuid()), 'did_type': DIDType.DATASET} for _ in range(2)])

    # Test with cutoff_date not defined
    try:
        core_config.remove_option('lifetime_model', 'cutoff_date')
    except (ConfigNotFound, NoSectionError):
        pass

    with pytest.raises(UnsupportedOperation):
        add_exception(datasets, root_account, pattern='wekhewfk', comments='This is a comment', expires_at=datetime.utcnow())

    # Test with cutoff_date wrongly defined
    core_config.set(section='lifetime_model', option='cutoff_date', value='wrong_value')
    with pytest.raises(UnsupportedOperation):
        add_exception(datasets, root_account, pattern='wekhewfk', comments='This is a comment', expires_at=datetime.utcnow())

    # Test with cutoff_date properly defined
    tomorrow = tomorrow.strftime('%Y-%m-%d')
    core_config.set(section='lifetime_model', option='cutoff_date', value=tomorrow)
    result = add_exception(datasets, root_account, pattern='wekhewfk', comments='This is a comment', expires_at=datetime.utcnow())

    # Check if the Not Existing DIDs are identified
    result_unknown = [(entry['scope'], entry['name']) for entry in result['unknown']]
    result_unknown.sort()
    unknown = [(entry['scope'], entry['name']) for entry in datasets[nb_datasets:nb_datasets + 2]]
    unknown.sort()
    assert result_unknown == unknown

    # Check if the DIDs not affected by the Lifetime Model are identified
    result_not_affected = [(entry['scope'], entry['name']) for entry in result['not_affected']]
    result_not_affected.sort()
    not_affected = list_dids[-1]
    assert result_not_affected == not_affected

    # Check if an exception was done for each datatype
    list_exceptions = list()
    for exception_id in result['exceptions']:
        dids = [(entry['scope'], entry['name']) for entry in result['exceptions'][exception_id]]
        dids.sort()
        list_exceptions.append(dids)

    for did in list_dids[:nb_datatype - 1]:
        assert did in list_exceptions


@skip_multivo(reason='only valid for ATLAS')
def test_lifetime_truncate_expiration(root_account, rse_factory, mock_scope, did_factory, rucio_client):
    """
    Test the duration of a lifetime exception is truncated if max_extension is defined
    """
    nb_datasets = 2
    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)
    tomorrow = today + timedelta(days=1)
    next_year = today + timedelta(days=365)
    rse, rse_id = rse_factory.make_posix_rse()
    datasets = [did_factory.make_dataset() for _ in range(nb_datasets)]
    metadata = str(uuid())
    for dataset in datasets:
        set_metadata(dataset['scope'], dataset['name'], 'datatype', metadata)
        set_metadata(dataset['scope'], dataset['name'], 'eol_at', yesterday)

    client_datasets = list()
    for dataset in datasets:
        client_datasets.append({'scope': dataset['scope'].external, 'name': dataset['name'], 'did_type': 'DATASET'})

    tomorrow = tomorrow.strftime('%Y-%m-%d')
    core_config.set(section='lifetime_model', option='cutoff_date', value=tomorrow)
    core_config.set(section='lifetime_model', option='max_extension', value=30)
    result = rucio_client.add_exception(client_datasets, account='root', pattern='wekhewfk', comments='This is a comment', expires_at=next_year)

    exception_id = list(result['exceptions'].keys())[0]
    exception = [exception for exception in rucio_client.list_exceptions() if exception['id'] == exception_id][0]
    assert exception['expires_at'] - exception['created_at'] < timedelta(31)
    assert exception['expires_at'] - exception['created_at'] > timedelta(29)


@skip_multivo(reason='only valid for ATLAS')
def test_lifetime_creation_client(root_account, rse_factory, mock_scope, did_factory, rucio_client):
    """
    Test the creation of a lifetime exception on the client side and that the exception can be listed with the client
    """
    nb_datatype = 3
    nb_datasets = 2 * nb_datatype
    yesterday = datetime.utcnow() - timedelta(days=1)
    tomorrow = datetime.utcnow() + timedelta(days=1)
    rse, rse_id = rse_factory.make_posix_rse()
    datasets = [did_factory.make_dataset() for _ in range(nb_datasets)]
    metadata = [str(uuid()) for _ in range(nb_datatype)]
    list_dids = []
    for cnt, meta in enumerate(metadata):
        dids = []
        for dataset in datasets[2 * cnt:2 * (cnt + 1)]:
            set_metadata(dataset['scope'], dataset['name'], 'datatype', meta)
            if cnt < nb_datatype - 1:
                set_metadata(dataset['scope'], dataset['name'], 'eol_at', yesterday)
            dids.append((dataset['scope'].external, dataset['name']))
        dids.sort()
        list_dids.append(dids)
    datasets.extend([{'scope': mock_scope, 'name': 'dataset_%s' % str(uuid()), 'did_type': DIDType.DATASET} for _ in range(2)])

    # Test with cutoff_date not defined
    try:
        core_config.remove_option('lifetime_model', 'cutoff_date')
    except (ConfigNotFound, NoSectionError):
        pass

    client_datasets = list()
    for dataset in datasets:
        client_datasets.append({'scope': dataset['scope'].external, 'name': dataset['name'], 'did_type': 'DATASET'})
    with pytest.raises(UnsupportedOperation):
        rucio_client.add_exception(client_datasets, account='root', pattern='wekhewfk', comments='This is a comment', expires_at=datetime.utcnow())

    # Test with cutoff_date wrongly defined
    core_config.set(section='lifetime_model', option='cutoff_date', value='wrong_value')
    with pytest.raises(UnsupportedOperation):
        rucio_client.add_exception(client_datasets, account='root', pattern='wekhewfk', comments='This is a comment', expires_at=datetime.utcnow())

    # Test with cutoff_date properly defined
    tomorrow = tomorrow.strftime('%Y-%m-%d')
    core_config.set(section='lifetime_model', option='cutoff_date', value=tomorrow)
    result = rucio_client.add_exception(client_datasets, account='root', pattern='wekhewfk', comments='This is a comment', expires_at=datetime.utcnow())

    # Check if the Not Existing DIDs are identified
    result_unknown = [(entry['scope'], entry['name']) for entry in result['unknown']]
    result_unknown.sort()
    unknown = [(entry['scope'], entry['name']) for entry in client_datasets[nb_datasets:nb_datasets + 2]]
    unknown.sort()
    assert result_unknown == unknown

    # Check if the DIDs not affected by the Lifetime Model are identified
    result_not_affected = [(entry['scope'], entry['name']) for entry in result['not_affected']]
    result_not_affected.sort()
    not_affected = list_dids[-1]
    assert result_not_affected == not_affected

    # Check if an exception was done for each datatype
    list_exceptions = list()
    for exception_id in result['exceptions']:
        dids = [(entry['scope'], entry['name']) for entry in result['exceptions'][exception_id]]
        dids.sort()
        list_exceptions.append(dids)

    for did in list_dids[:nb_datatype - 1]:
        assert did in list_exceptions

    exceptions = [exception['id'] for exception in rucio_client.list_exceptions()]
    for exception_id in result['exceptions']:
        assert exception_id in exceptions


@skip_multivo(reason='only valid for ATLAS')
@pytest.mark.dirty
@pytest.mark.noparallel(reason='Uses daemons. Write a configuration file')
def test_atropos(root_account, rse_factory, mock_scope, did_factory, rucio_client):
    """
    Test the behaviour of atropos
    """
    today = datetime.utcnow()
    check_date = datetime.utcnow() + timedelta(days=365)
    check_date = check_date.isoformat().split('T')[0]

    # Define a policy
    lifetime_dir = '/opt/rucio/etc/policies'
    os.makedirs('/opt/rucio/etc/policies', exist_ok=True)
    lifetime_policy = [{'name': 'Test', 'include': {'datatype': ['RAW'], 'project': ['data%']}, 'age': '6', 'extension': '1'}]
    with open('%s/config_other.json' % lifetime_dir, 'w') as outfile:
        json.dump(lifetime_policy, outfile)
    REGION.invalidate()
    nb_datasets = 2
    today = datetime.utcnow()
    rse, rse_id = rse_factory.make_posix_rse()
    datasets = [did_factory.make_dataset() for _ in range(nb_datasets)]
    rules = list()
    expiration_date = None

    # Check that the eol_at is properly set
    # Rule on dataset 0 that matches the policy should get an eol_at
    # Rule on dataset 1 that doesn't matches the policy should not get an eol_at
    for cnt, dataset in enumerate(datasets):
        if cnt == 0:
            set_metadata(dataset['scope'], dataset['name'], 'datatype', 'RAW')
            set_metadata(dataset['scope'], dataset['name'], 'project', 'data')
        rule_ids = add_rule(dids=[{'scope': dataset['scope'], 'name': dataset['name']}], account=root_account, copies=1, rse_expression=rse, grouping='DATASET', weight=None, lifetime=None, locked=None, subscription_id=None)
        rules.append(rule_ids[0])
        rule = get_rule(rule_ids[0])
        if cnt == 0:
            expiration_date = rule['eol_at']
            assert expiration_date is not None
            assert expiration_date - today < timedelta(181)
            assert expiration_date - today > timedelta(179)
        else:
            assert rule['eol_at'] is None

    # Run atropos in dry-run mode to set eol_at on the dataset
    # Dataset 0 should get eol_at
    # Dataset 1 should not get eol_at
    atropos(date_check=datetime.strptime(check_date, '%Y-%m-%d'), dry_run=True, grace_period=86400,
            once=True, unlock=False, spread_period=0, purge_replicas=False, sleep_time=60)

    for cnt, dataset in enumerate(datasets):
        meta = get_metadata(dataset['scope'], dataset['name'])
        if cnt == 0:
            assert meta['eol_at'] is not None
            assert meta['eol_at'] == expiration_date
        else:
            assert meta['eol_at'] is None

    # Clean-up
    os.remove('/opt/rucio/etc/policies/config_other.json')
