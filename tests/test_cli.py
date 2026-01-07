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

import json
import logging
import os
import random
import re
import shlex
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from lib.rucio.tests.common import file_generator
from rucio.common.checksum import md5
from rucio.common.utils import generate_uuid, render_json
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import account_name_generator, execute, rse_name_generator, scope_name_generator


def test_rucio_version():
    """CLIENT(USER): Rucio version"""
    cmd = 'bin/rucio --version'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert 'rucio' in out or 'rucio' in err


def test_rucio_ping(rucio_client):
    """CLIENT(USER): Rucio ping"""
    cmd = f'rucio --host {rucio_client.host} ping'
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert 'ERROR' not in err


def test_rucio_config_arg():
    """CLIENT(USER): Rucio config argument"""
    cmd = 'rucio --config errconfig ping'
    exitcode, _, err = execute(cmd)
    assert 'Could not load Rucio configuration file' in err and re.match('.*errconfig.*$', err, re.DOTALL)
    assert exitcode == 1


@pytest.mark.parametrize("cmd", [
    lambda a: f"rucio-admin --legacy account add {a}",
    lambda a: f"rucio account add {a} USER "
], ids=["legacy", "current"])
@pytest.mark.dirty(reason="Creates a new account on vo=def")
def test_add_account(cmd):
    """CLIENT(ADMIN): Add account"""
    tmp_val = account_name_generator()
    exitcode, out, _ = execute(cmd(tmp_val))
    assert f'Added new account: {tmp_val}\n' in out
    assert exitcode == 0


@pytest.mark.parametrize("cmd", [
    "rucio-admin --legacy account list",
    "rucio account list"
], ids=["legacy", "current"])
def test_list_account(cmd, rucio_client, random_account_factory):
    """CLIENT(ADMIN): List accounts"""
    n_accounts = 5
    tmp_accounts = [random_account_factory().external for _ in range(n_accounts)]
    for account in tmp_accounts:
        rucio_client.add_account_attribute(account=account, key='test_list_account', value='true')

    _, out, _ = execute(cmd)
    assert tmp_accounts[0] in out
    assert tmp_accounts[-1] in out  # Test by induction

    filter_cmd = f"{cmd} --filter test_list_account=true"
    _, out, _ = execute(filter_cmd)
    assert set([o for o in out.split("\n") if o != '']) == set(tmp_accounts)  # There's a little '' printed after

    filter_cmd = f"{cmd} --filter test_list_account=true --csv"
    _, out, _ = execute(filter_cmd)
    assert set(o.rstrip('\n') for o in out.split(',')) == set(tmp_accounts)  # Last obj in list has a `\n` included


def test_whoami():
    """CLIENT(USER): Rucio whoami"""
    cmd = 'rucio whoami'
    _, out, err = execute(cmd)
    assert 'account' in out
    assert "ERROR" not in err


@pytest.mark.parametrize("add_cmd,list_cmd,del_cmd", [
    (
        lambda a: f'rucio-admin --legacy identity add --account {a} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH',
        lambda a: f'rucio-admin --legacy account list-identities {a}',
        lambda a: f'rucio-admin --legacy identity delete --account {a} --type GSS --id jdoe@CERN.CH'
    ),
    (
        lambda a: f'rucio account identity add {a} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH',
        lambda a: f'rucio account identity list {a}',
        lambda a: f'rucio account identity remove {a} --type GSS --id jdoe@CERN.CH',
    )
], ids=["legacy", "current"])
def test_gss_identity(add_cmd, list_cmd, del_cmd, random_account):
    """CLIENT(ADMIN): Add/list/delete identity"""

    exitcode, out, _ = execute(add_cmd(random_account))
    assert f'Added new identity to account: jdoe@CERN.CH-{random_account}\n' in out

    exitcode, out, _ = execute(list_cmd(random_account))
    assert exitcode == 0
    assert 'jdoe@CERN.CH' in out

    exitcode, out, _ = execute(del_cmd(random_account))
    assert 'Deleted identity: jdoe@CERN.CH\n' in out

    exitcode, out, _ = execute(list_cmd(random_account))
    assert 'jdoe@CERN.CH' not in out


@pytest.mark.parametrize("add_cmd,del_cmd", [
    (
        lambda a, id: f'rucio-admin --legacy identity add --account {a} --type OIDC --id "{id}" --email jdoe@CERN.CH',
        lambda a, id: f'rucio-admin --legacy identity delete --account {a} --type OIDC --id "{id}"'
    ),
    (
        lambda a, id: f'rucio account identity add {a} --type OIDC --id "{id}" --email jdoe@CERN.CH',
        lambda a, id: f'rucio account identity remove {a} --type OIDC --id "{id}"',
    )
], ids=["legacy", "current"])
def test_oidc_identity(add_cmd, del_cmd, random_account, rucio_client):

    id = "CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch"
    exitcode, out, _ = execute(add_cmd(random_account, id))
    assert exitcode == 0
    assert f'Added new identity to account: {id}-{random_account}\n' in out

    exitcode, _, err = execute(del_cmd(random_account, id))
    assert exitcode == 0
    assert "ERROR" not in err

    ids = [i['type'] for i in rucio_client.list_identities(account=random_account.external)]
    assert 'OIDC' not in ids


@pytest.mark.parametrize("add_cmd,list_cmd,del_cmd", [
    (
        lambda a: f'rucio-admin --legacy account add-attribute {a} --key test_attribute_key --value true',
        lambda a: f'rucio-admin --legacy account list-attributes {a}',
        lambda a: f'rucio-admin --legacy account delete-attribute {a} --key test_attribute_key'
    ),
    (
        lambda a: f'rucio account attribute add {a} --key test_attribute_key --value true',
        lambda a: f'rucio account attribute list {a}',
        lambda a: f'rucio account attribute remove {a} --key test_attribute_key'
    )
], ids=["legacy", "current"])
def test_attributes(add_cmd, list_cmd, del_cmd, random_account):
    """CLIENT(ADMIN): Add/List/Delete attributes"""

    exitcode, _, err = execute(add_cmd(random_account))
    assert exitcode == 0
    assert "ERROR" not in err
    # list attributes
    exitcode, out, err = execute(list_cmd(random_account))
    assert exitcode == 0
    assert "ERROR" not in err
    assert 'test_attribute_key' in out

    # delete attribute to the account
    exitcode, _, err = execute(del_cmd(random_account))
    assert exitcode == 0
    assert "ERROR" not in err


@pytest.mark.parametrize("add_cmd,list_filter_cmd,list_all_cmd", [
    (
        lambda a, s: f"rucio-admin --legacy scope add --account {a} --scope {s}",
        lambda a: f'rucio-admin --legacy scope list --account {a}',
        lambda: "rucio-admin --legacy scope list"

    ),
    (
        lambda a, s: f"rucio-admin --legacy scope add --account {a} --scope {s}",
        lambda a: f'rucio --legacy list-scopes --account {a}',
        lambda: "rucio --legacy list-scopes"
    ),
    (
        lambda a, s: f"rucio scope add {s} --account {a}",
        lambda a: f"rucio scope list --account {a}",
        lambda: "rucio scope list"
    )
], ids=["legacy-admin", "legacy-base", "current"])
@pytest.mark.dirty(reason="Creates a new scope on vo=def")
def test_scope(add_cmd, list_filter_cmd, list_all_cmd, random_account):
    """CLIENT(ADMIN): Add/list scope"""

    tmp_scp = scope_name_generator()
    exitcode, out, _ = execute(add_cmd(random_account, tmp_scp))
    assert exitcode == 0
    assert f'Added new scope to {random_account}: {tmp_scp}' in out

    exitcode, out, _ = execute(list_filter_cmd(random_account))
    assert exitcode == 0
    assert tmp_scp in out

    cmd = f"{list_filter_cmd(random_account)} --csv"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert tmp_scp in out.split('\n')

    exitcode, out, err = execute(list_all_cmd())
    assert exitcode == 0
    assert tmp_scp in out

    cmd = f"{list_all_cmd()} --csv"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert tmp_scp in out.split('\n')


@pytest.mark.parametrize("cmd,msg", [
    (lambda n: f'rucio-admin --legacy rse add {n}', "new deterministic RSE"),
    (lambda n: f'rucio-admin --legacy rse add {n} --non-deterministic', "new non-deterministic RSE"),
    (lambda n: f'rucio rse add {n}', "new deterministic RSE"),
    (lambda n: f'rucio rse add {n} --non-deterministic', "new non-deterministic RSE")
], ids=["legacy-deterministic", "legacy-non-deterministic", "current-deterministic", "current-non-deterministic"])
@pytest.mark.dirty(reason="RSEs are not deleted after the test")
def test_add_rse(cmd, msg, rucio_client):
    """CLIENT(ADMIN): Add RSE"""
    tmp_val = rse_name_generator()
    _, out, _ = execute(cmd(tmp_val))
    assert f'Added {msg}: {tmp_val}\n' in out

    rses = [rse for rse in rucio_client.list_rses()]
    assert tmp_val in [rse['rse'] for rse in rses]
    is_deterministic = "new deterministic RSE" == msg
    assert [rse for rse in rses if rse['rse'] == tmp_val][0]['deterministic'] is is_deterministic


@pytest.mark.parametrize("cmd", [
    "rucio-admin --legacy rse list",
    "rucio --legacy list-rses",
    "rucio rse list"
], ids=["legacy-admin", "legacy-base", "current"])
def test_list_rses(cmd, rse_factory):
    """CLIENT(USER/ADMIN): List RSEs"""
    # TODO Test filter
    rse, _ = rse_factory.make_posix_rse()
    _, out, _ = execute(cmd)
    assert rse in out

    # Expected output is a new RSE on each line
    csv_cmd = f'{cmd} --csv'
    _, out, _ = execute(csv_cmd)
    assert rse in out.split('\n')


@pytest.mark.parametrize("base_cmd", [
    "rucio-admin --legacy rse add-distance --distance 1 --ranking 1",
    "rucio rse distance add --distance 1 "
], ids=['legacy', 'current'])
def test_rse_add_distance(base_cmd, rse_factory):
    """CLIENT (ADMIN): Add distance to RSE"""
    # add RSEs
    rse_name_1, _ = rse_factory.make_posix_rse()
    rse_name_2, _ = rse_factory.make_posix_rse()

    # add distance between the RSEs
    cmd = f'{base_cmd} {rse_name_1} {rse_name_2}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    cmd = f'{base_cmd} {rse_name_2} {rse_name_1}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0

    # add duplicate distance
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert f'Distance from {rse_name_2} to {rse_name_1} already exists!' in err


@pytest.mark.parametrize("base_cmd", [
    "rucio-admin --legacy rse delete-distance",
    "rucio rse distance remove"
], ids=['legacy', 'current'])
def test_rse_delete_distance(base_cmd, rse_factory, rucio_client):
    """CLIENT (ADMIN): Delete distance to RSE"""
    # add RSEs
    rse_name_1, _ = rse_factory.make_posix_rse()
    rse_name_2, _ = rse_factory.make_posix_rse()

    # add distance between the RSEs
    rucio_client.add_distance(rse_name_1, rse_name_2, parameters={'distance': 1, 'ranking': 1})

    # delete distance OK
    cmd = f'{base_cmd} {rse_name_1} {rse_name_2}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Deleted distance information from {rse_name_1} to {rse_name_2}" in out

    # delete distance RSE not found
    cmd = f'{base_cmd} {rse_name_1} {generate_uuid()}'
    exitcode, out, err = execute(cmd)
    assert 'RSE does not exist.' in err


@pytest.mark.parametrize("cmd", [
    lambda d: f"rucio --legacy add-dataset {d}",
    lambda d: f"rucio did add {d} --type dataset"
], ids=['legacy', 'current'])
def test_create_dataset(cmd, rucio_client, mock_scope):
    """CLIENT(USER): Rucio add dataset"""
    scope = mock_scope.external
    tmp_name = f"{scope}:DSet_{generate_uuid()}"
    exitcode, out, err = execute(cmd(tmp_name))
    assert exitcode == 0
    assert re.search('Added ' + tmp_name, out) is not None
    assert tmp_name in [f"{scope}:{did}" for did in rucio_client.list_dids(scope=scope, did_type="dataset", filters={})]


@pytest.mark.parametrize("cmd", [
    lambda t, f: f"rucio --legacy attach {t} {f}",
    lambda t, f: f"rucio did content add {f} -to {t}"
], ids=['legacy', 'current'])
def test_add_files_to_dataset(cmd, rucio_client, rse_factory, mock_scope, did_factory):
    """CLIENT(USER): Rucio add files to dataset"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    temp_dataset = did_factory.make_dataset(scope=scope)
    temp_dataset_name = f"{scope}:{temp_dataset['name']}"
    # Files need to be registered on an RSE to be attached to a DID
    temp_file1 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']
    temp_file2 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    # add files to dataset
    exitcode, _, _ = execute(cmd(temp_dataset_name, f"{scope}:{temp_file1} {scope}:{temp_file2}"))
    assert exitcode == 0

    names = [d['name'] for d in rucio_client.list_content(scope, temp_dataset['name'])]
    # find the added files
    assert temp_file1 in names
    assert temp_file2 in names


@pytest.mark.parametrize("cmd", [
    lambda t, f: f"rucio --legacy detach {t} {f}",
    lambda t, f: f"rucio did content remove {f} --from-did {t}"
], ids=['legacy', 'current'])
def test_detach_files_dataset(cmd, rucio_client, rse_factory, did_factory):
    """CLIENT(USER): Rucio detach files to dataset"""
    rse, _ = rse_factory.make_posix_rse()
    temp_dataset = did_factory.upload_test_dataset(rse, nb_files=3)
    scope = temp_dataset[0]['dataset_scope']
    temp_dataset_name = f"{scope}:{temp_dataset[0]['dataset_name']}"
    temp_file1 = temp_dataset[0]['did_name']
    temp_file2 = temp_dataset[1]['did_name']
    temp_file3 = temp_dataset[2]['did_name']

    exitcode, _, _ = execute(cmd(temp_dataset_name, f"{scope}:{temp_file2} {scope}:{temp_file3}"))
    assert exitcode == 0

    # searching for the file in the new dataset
    names = [d['name'] for d in rucio_client.list_content(scope, temp_dataset[0]['dataset_name'])]
    # find the added files
    assert temp_file1 in names  # First file in the dataset
    # The second two are not
    assert temp_file2 not in names
    assert temp_file3 not in names


@pytest.mark.parametrize("cmd", [
    lambda t, f: f"rucio --legacy attach {t} {f}",
    lambda t, f: f"rucio did content add {f} -to {t}"
], ids=['legacy', 'current'])
def test_attach_file_twice(cmd, rse_factory, did_factory):
    """CLIENT(USER): Rucio attach a file twice"""
    # Attach files to a dataset using the attach method
    rse, _ = rse_factory.make_posix_rse()
    temp_dataset = did_factory.upload_test_dataset(rse_name=rse, size=1, nb_files=1)
    scope = temp_dataset[0]['dataset_scope']
    temp_dataset_name = f"{scope}:{temp_dataset[0]['dataset_name']}"
    temp_file1 = temp_dataset[0]['did_name']

    # attach the files to the dataset
    exitcode, out, err = execute(cmd(temp_dataset_name, f"{scope}:{temp_file1}"))
    assert exitcode != 0
    assert re.search("The file already exists", err) is not None


@pytest.mark.parametrize("cmd", [
    lambda t, f: f"rucio --legacy attach {t} {f}",
    lambda t, f: f"rucio did content add -to {t} {f}"
], ids=['legacy', 'current'])
def test_attach_dataset_twice(cmd, did_factory, mock_scope, rucio_client):
    """ CLIENT(USER): Rucio attach a dataset twice """
    scope = mock_scope.external
    container = did_factory.make_container(scope=mock_scope)['name']
    dataset = did_factory.make_dataset(scope=mock_scope)['name']

    # Attach dataset to container
    exitcode, out, err = execute(cmd(f"{scope}:{container}",  f"{scope}:{dataset}"))
    assert exitcode == 0

    # Attach again
    exitcode, out, err = execute(cmd(f"{scope}:{container}",  f"{scope}:{dataset}"))
    assert exitcode != 0
    assert re.search("Data identifier already added to the destination content", err) is not None

    # This restraint does not apply to batched mode
    n_dids = 1400
    dids = [{'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'} for _ in range(0, n_dids)]
    rucio_client.add_dids(dids)

    batched_cmd = cmd(f"{scope}:{container}", "")
    for did in dids:
        batched_cmd += f' {mock_scope}:{did["name"]}'
    exitcode, out, err = execute(batched_cmd)
    assert exitcode == 0
    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, container)]
    assert all([did['name'] in names for did in dids])

    # Second attach should not fail
    exitcode, out, err = execute(batched_cmd)
    assert exitcode == 0
    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, container)]
    assert all([did['name'] in names for did in dids])

    # Adding a new one will not fail either
    new_did = {'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'}
    rucio_client.add_dids([new_did])
    dids.append(new_did)
    batched_cmd = cmd(f'{scope}:{container}', '')
    for did in dids:
        batched_cmd += f' {mock_scope}:{did["name"]}'
    exitcode, out, err = execute(batched_cmd)
    assert exitcode == 0
    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, container)]
    assert new_did['name'] in names


@pytest.mark.parametrize("cmd", [
    lambda t, f: f"rucio --legacy detach {t} {f}",
    lambda t, f: f"rucio did content remove -to {t} {f}"
], ids=['legacy', 'current'])
def test_detach_non_existing_file(cmd, did_factory):
    """CLIENT(USER): Rucio detach a non existing file"""
    dataset = did_factory.make_dataset()
    scope = dataset['scope']
    name = dataset['name']
    exitcode, out, err = execute(cmd(f"{scope}:{name}" f"{scope}:file_ghost"))
    assert exitcode != 0
    assert re.search("Data identifier not found.", err) is not None


@pytest.mark.parametrize("cmd", [
    lambda f: f"rucio --legacy list-file-replicas {f}",
    lambda f: f"rucio replica list file {f}"
], ids=['legacy', 'current'])
def test_list_blocklisted_replicas(cmd, rucio_client, rse_factory, did_factory):
    """CLIENT(USER): Rucio list replicas"""
    # add rse
    rse, _ = rse_factory.make_posix_rse()
    rucio_client.add_protocol(
        rse,
        params={
            "scheme": "file",
            "prefix": "/rucio",
            "port": 0,
            "impl": "rucio.rse.protocols.posix.Default",
            "domain_json": '{"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0}'
        })

    # Add a dataset with a file to the rse
    temp_dataset = did_factory.upload_test_dataset(rse, nb_files=1)
    temp_dataset_name = f"{temp_dataset[0]['dataset_scope']}:{temp_dataset[0]['dataset_name']}"

    # Listing the replica should work before blocklisting the RSE
    exitcode, out, err = execute(cmd(temp_dataset_name))
    assert rse in out

    # Blocklist the rse
    rucio_client.update_rse(rse, {"availability_read": False})

    # list-file-replicas should, by default, list replicas from blocklisted rses
    exitcode, out, err = execute(cmd(temp_dataset_name))
    assert rse in out


@pytest.mark.parametrize("cmd,list_cmd", [
    (
        lambda n, copies: f"rucio --legacy add-rule {n} {copies} 'spacetoken=ATLASSCRATCHDISK'",
        lambda n: f"rucio --legacy list-rules {n}"
    ),
    (
        lambda n, copies: f"rucio rule add {n} --copies {copies} --rses 'spacetoken=ATLASSCRATCHDISK'",
        lambda n: f"rucio rule list --did {n}"
    )
], ids=['legacy', 'current'])
def test_create_rule(cmd, list_cmd, did_factory, rse_factory, rucio_client):
    """CLIENT(USER): Rucio add rule"""
    base_rse, _ = rse_factory.make_posix_rse()

    # add files
    temp_file1 = did_factory.upload_test_file(rse_name=base_rse)
    temp_file_name = temp_file1['name']
    temp_scope = temp_file1['scope']
    account = rucio_client.whoami()['account']
    n_replicas = 3
    # Three copies of the file required, we need to make 3 temp rses
    # remove limit and set attributes
    for _ in range(n_replicas):
        temp_rse, _ = rse_factory.make_posix_rse()
        rucio_client.set_local_account_limit(account, temp_rse, -1)
        rucio_client.add_rse_attribute(temp_rse, 'spacetoken', 'ATLASSCRATCHDISK')

    # add rules
    exitcode, out, err = execute(cmd(f"{temp_scope}:{temp_file_name}", n_replicas))
    print(out, err)
    assert exitcode == 0
    assert "ERROR" not in err
    rule = out.split('\n')[-2]
    assert re.match(r'^\w+$', rule)

    # check if rule exist for the file
    exitcode, out, err = execute(list_cmd(f"{temp_scope}:{temp_file_name}"))
    assert re.search(rule, out) is not None


@pytest.mark.parametrize("cmd", [
    lambda n, delay: f"rucio --legacy add-rule --delay-injection {delay} {n} 1 'spacetoken=ATLASRULEDELAYED'",
    lambda n, delay: f"rucio rule add {n} --copies 1 --rses 'spacetoken=ATLASRULEDELAYED' --delay-injection {delay}"
], ids=['legacy', 'current'])
def test_create_rule_delayed(cmd, rucio_client, rse_factory, did_factory):
    """CLIENT(USER): Rucio add rule delayed"""
    base_rse, _ = rse_factory.make_posix_rse()
    # add files
    temp_file1 = did_factory.upload_test_file(rse_name=base_rse)
    temp_file_name = temp_file1['name']
    temp_scope = temp_file1['scope']
    # remove limit and set attributes
    account = rucio_client.whoami()['account']
    temp_rse, _ = rse_factory.make_posix_rse()
    rucio_client.set_local_account_limit(account, temp_rse, -1)
    rucio_client.add_rse_attribute(temp_rse, 'spacetoken', 'ATLASRULEDELAYED')

    # try adding rule with an incorrect delay-injection. Must fail
    exitcode, out, err = execute(cmd(f"{temp_scope}:{temp_file_name}", "jkdsf"))
    assert exitcode == 2  # Fails due to invalid value in argparse

    # Add a correct rule
    exitcode, out, err = execute(cmd(f"{temp_scope}:{temp_file_name}", 3600))
    assert exitcode == 0
    assert "ERROR" not in err
    rule = out.split('\n')[-2]

    # TODO Bespoke test for rule show
    rule_info = rucio_client.get_replication_rule(rule)

    # Check for ok/replicating/stuck
    assert rule_info['locks_ok_cnt'] == 0
    assert rule_info['locks_replicating_cnt'] == 0
    assert rule_info['locks_stuck_cnt'] == 0

    # Check for INJECT state
    assert rule_info['state'] == 'INJECT'

    # Created at should be about 3600 seconds in the future
    created_at = rule_info['created_at'].replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    assert now + timedelta(seconds=3550) < created_at < now + timedelta(seconds=3650)


@pytest.mark.parametrize("cmd", [
    lambda id: f"rucio --legacy delete-rule {id}",
    lambda id: f"rucio rule remove {id}"
], ids=['legacy', 'current'])
def test_delete_rule(cmd, did_factory, rse_factory, rucio_client):
    """CLIENT(USER): rule deletion - delete 2 rules and verify it stays on the original RSE"""
    base_rse, _ = rse_factory.make_posix_rse()

    temp_file1 = did_factory.upload_test_file(rse_name=base_rse)
    temp_file1['scope'] = temp_file1['scope'].external
    temp_file_name = temp_file1['name']

    # remove limit and set attributes
    account = rucio_client.whoami()['account']
    temp_rse, _ = rse_factory.make_posix_rse()
    rucio_client.set_local_account_limit(account, temp_rse, -1)
    rucio_client.add_rse_attribute(temp_rse, 'spacetoken', 'ATLASDELETERULE')

    # Add the rule
    rucio_client.add_replication_rule(
        dids=[temp_file1],
        copies=1,
        rse_expression='spacetoken=ATLASDELETERULE',
    )

    # TODO Bespoke test for rule list
    rules = rucio_client.list_replication_rules(filters={'scope': temp_file1['scope'], 'name': temp_file_name})
    for rule in rules:
        exitcode, out, err = execute(cmd(rule['id']))
        assert exitcode == 0, f"Failed deleting rule with ID {rule['id']}"

    # Check if the file is still on the original RSE
    replicas = rucio_client.list_replicas(dids=[temp_file1])
    rses = [rse for r in replicas for rse in r['rses'].keys()]
    assert base_rse in rses
    # Did not make it to the new RSE
    assert temp_rse not in rses


@pytest.mark.parametrize("cmd", [
    lambda id, rse: f"rucio --legacy move-rule {id} {rse}",
    lambda id, rse: f"rucio rule move {id} --rses {rse}"
], ids=['legacy', 'current'])
@pytest.mark.dirty(reason="Cleanup can fail to complete because of child rules in client tests")
def test_move_rule(cmd, did_factory, rse_factory, rucio_client):
    """CLIENT(USER): Rucio move rule"""
    base_rse, _ = rse_factory.make_posix_rse()

    temp_file1 = did_factory.upload_test_file(rse_name=base_rse)
    temp_file1['scope'] = temp_file1['scope'].external
    temp_file_name = temp_file1['name']

    # remove limit and set attributes
    account = rucio_client.whoami()['account']
    # Add 3 new rses with the same attributes
    for _ in range(3):
        temp_rse, _ = rse_factory.make_posix_rse()
        rucio_client.set_local_account_limit(account, temp_rse, -1)
        rucio_client.add_rse_attribute(temp_rse, 'spacetoken', 'ATLASMOVERULE')

    # Add the rule
    [rule_id] = rucio_client.add_replication_rule(
        copies=3,
        rse_expression='spacetoken=ATLASMOVERULE',
        dids=[temp_file1]
    )

    # move rule
    new_rule_expr = "'spacetoken=ATLASMOVERULE|spacetoken=ATLASSD'"  # Expression includes the 3 existing RSEs
    exitcode, out, err = execute(cmd(rule_id, new_rule_expr))
    assert exitcode == 0
    assert "ERROR" not in err
    new_rule = out.split('\n')[-2]  # trimming new line character

    # Check for new rule
    rules = rucio_client.list_replication_rules(filters={'scope': temp_file1['scope'], 'name': temp_file_name})
    rule_ids = [rule['id'] for rule in rules]

    assert new_rule in rule_ids
    assert rule_id in rule_ids  # Does not delete the old rule when moved


@pytest.mark.parametrize("cmd", [
    lambda id, rse, source, activity: f"rucio --legacy move-rule {id} '{rse}' --source-replica-expression '{source}' --activity '{activity}'",
    lambda id, rse, source, activity: f"rucio rule move {id} --rses '{rse}' --source-rses '{source}' --activity '{activity}'"
], ids=['legacy', 'current'])
def test_move_rule_with_arguments(cmd, rse_factory, did_factory, rucio_client):
    """CLIENT(USER): Rucio move rule with a new activity"""
    base_rse, _ = rse_factory.make_posix_rse()

    temp_file1 = did_factory.upload_test_file(rse_name=base_rse)
    temp_file1['scope'] = temp_file1['scope'].external
    temp_file_name = temp_file1['name']

    # remove limit and set attributes
    account = rucio_client.whoami()['account']
    # Add 3 new rses with the same attributes
    for _ in range(3):
        temp_rse, _ = rse_factory.make_posix_rse()
        rucio_client.set_local_account_limit(account, temp_rse, -1)
        rucio_client.add_rse_attribute(temp_rse, 'spacetoken', 'ATLASARGSMOVERULEARGS')

    # Add the rule
    [rule_id] = rucio_client.add_replication_rule(
        copies=3,
        rse_expression='spacetoken=ATLASARGSMOVERULEARGS',
        dids=[temp_file1]
    )

    # move rule
    new_rule_expr = "spacetoken=ATLASARGSMOVERULEARGS|spacetoken=ATLASSD"
    new_rule_activity = "No User Subscription"
    new_rule_source_replica_expression = "spacetoken=ATLASARGSMOVERULEARGS|spacetoken=ATLASSD"
    exitcode, out, err = execute(cmd(rule_id, new_rule_expr, new_rule_source_replica_expression, new_rule_activity))
    print(out, err)
    assert exitcode == 0
    assert "ERROR" not in err
    new_rule_id = out.split('\n')[-2]  # trimming new line character

    # Verify rule was made
    rules = rucio_client.list_replication_rules(filters={'scope': temp_file1['scope'], 'name': temp_file_name})
    assert new_rule_id in [rule['id'] for rule in rules]

    # Verify new details are changed
    rule_info = rucio_client.get_replication_rule(new_rule_id)
    assert new_rule_activity == rule_info["activity"]
    assert new_rule_source_replica_expression == rule_info["source_replica_expression"]


@pytest.mark.parametrize("cmd", [
    lambda did: f"rucio --legacy list-dids {did} --recursive",
    lambda did: f"rucio did list {did} --recursive"
], ids=['legacy', 'current'])
def test_list_did_recursive(cmd, did_factory, mock_scope, rucio_client):
    """ CLIENT(USER): List did recursive """
    scope = mock_scope.external
    # Setup nested collections
    tmp_container_1 = did_factory.make_container(scope=scope)
    tmp_container_2 = did_factory.make_container(scope=scope)
    tmp_container_2['scope'] = scope
    tmp_container_3 = did_factory.make_container(scope=scope)
    tmp_container_3['scope'] = scope

    # Container 3 inside container 2, container 2 inside container 1
    rucio_client.attach_dids(scope, tmp_container_1['name'], [tmp_container_2])
    rucio_client.attach_dids(scope, tmp_container_2['name'], [tmp_container_3])

    # All attached DIDs are expected
    exitcode, out, err = execute(cmd(f'{scope}:{tmp_container_1["name"]}'))
    assert exitcode == 0
    assert tmp_container_1['name'] in out
    assert tmp_container_2['name'] in out
    assert tmp_container_3['name'] in out

    # Wildcards are not allowed to use with --recursive
    exitcode, out, err = execute(cmd(f'{scope}:*'))
    assert exitcode != 0
    assert re.search("Option recursive cannot be used with wildcards", err) is not None


@pytest.mark.parametrize("cmd", [
    lambda did: f"rucio --legacy attach {did} ",
    lambda did: f"rucio did content add --to-did {did} "
], ids=['legacy', 'current'])
def test_attach_many_dids(cmd, mock_scope, did_factory, rucio_client):
    """ CLIENT(USER): Rucio attach many (>1000) DIDs to ensure batching is done correctly, checks the `--from-file` option """
    n_dids = 1400

    # Setup making the dids
    temp_dataset = did_factory.make_container(scope=mock_scope)
    temp_dataset_name = f"{mock_scope}:{temp_dataset['name']}"

    # Note: upload_test_dataset takes FAR too long (10+ minutes) to run for this number of dids - just add rucio_client attaching to the mock container
    dids = [{'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'} for _ in range(0, n_dids)]
    rucio_client.add_dids(dids)

    # Attaching over 1000 DIDs with CLI
    attach_cmd = cmd(temp_dataset_name)
    for did in dids:
        attach_cmd += f' {mock_scope}:{did["name"]}'
    exitcode, out, err = execute(attach_cmd)
    assert exitcode == 0

    # Checking if the execution was successful and if the DIDs belong together
    assert 'DIDs successfully attached' in out
    assert "You are trying to attach too much DIDs. Therefore they will be chunked and attached in multiple commands." in err

    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, temp_dataset['name'])]
    assert len(names) == n_dids
    assert all([did['name'] in names for did in dids])

    # make a similarly large dataset, and then use the --from-file option
    dids = [{'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'} for _ in range(0, n_dids)]
    rucio_client.add_dids(dids)

    with tempfile.NamedTemporaryFile(delete=False) as did_file:
        with open(did_file.name, 'w') as f:
            for file in dids:
                f.write(f"{mock_scope}:{file['name']}\n")

        attach_cmd = f'{cmd(temp_dataset_name)} --from-file {did_file.name}'
        exitcode, out, err = execute(attach_cmd)
        assert exitcode == 0

        names = [d['name'] for d in rucio_client.list_content(mock_scope.external, temp_dataset['name'])]
        assert all([did['name'] in names for did in dids])


@pytest.mark.parametrize("cmd", [
    lambda did, f: f"rucio --legacy attach {did} --from-file {f}",
    lambda did, f: f"rucio did content add --to-did {did} --from-file {f}"
], ids=['legacy', 'current'])
def test_attach_dids_from_file(cmd, rse_factory, mock_scope, did_factory, rucio_client):
    """ CLIENT(USER): Rucio attach from a file """
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    temp_dataset = did_factory.make_dataset(scope=scope)
    temp_dataset_name = f"{scope}:{temp_dataset['name']}"
    temp_file1 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']
    temp_file2 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']
    temp_file3 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    # Setup data with file
    with tempfile.NamedTemporaryFile() as did_file:

        with open(did_file.name, 'w') as f:
            f.write(f"{scope}:{temp_file1}\n")
            f.write(f"{scope}:{temp_file2}\n")
            f.write(f"{scope}:{temp_file3}\n")
            f.close()

        # Attaching over 1000 files per file
        exitcode, out, err = execute(cmd(temp_dataset_name, did_file.name))

    assert exitcode == 0
    assert 'DIDs successfully attached' in out

    names = [d['name'] for d in rucio_client.list_content(scope, temp_dataset['name'])]
    assert len(names) == 3
    assert (temp_file1 in names) and (temp_file2 in names) and (temp_file3 in names)


@pytest.mark.parametrize("cmd", [
    lambda f: f"rucio-admin --legacy data import {f}",
    lambda f: f"rucio upload {f}"
], ids=['legacy', 'current'])
def test_import_data(cmd, rse_factory, rucio_client):
    """ CLIENT(ADMIN): Import data into rucio"""

    n_rses = 5
    rses = []
    for _ in range(n_rses):
        temp_rse, _ = rse_factory.make_posix_rse()
        rses.append(temp_rse)

    data = {"rses": {rse: {'country_name': "ATLASIMPORTDATA"} for rse in rses}}

    with tempfile.NamedTemporaryFile(suffix=".json") as tmp_file:
        with open(tmp_file.name, 'w') as f:
            f.write(render_json(**data))
            f.close()

        exitcode, out, err = execute(cmd(tmp_file.name))
    assert exitcode == 0
    assert re.search('Data successfully imported', out) is not None

    updated_rses = [rse['rse'] for rse in rucio_client.list_rses("country_name=ATLASIMPORTDATA")]
    assert all([rse in updated_rses for rse in rses])


@pytest.mark.parametrize("cmd", [
    lambda f: f"rucio-admin --legacy data export {f}",
    lambda f: f"rucio upload {f}"
], ids=['legacy', 'current'])
@pytest.mark.noparallel(reason='fails when run in parallel')
def test_export_data(cmd):
    """ CLIENT(ADMIN): Export data from rucio"""
    with tempfile.NamedTemporaryFile(suffix=".json") as tmp_file:

        exitcode, out, err = execute(cmd(tmp_file.name))

        assert exitcode == 0
        assert 'Data successfully exported' in out
        assert os.path.exists(tmp_file.name)

        with open(tmp_file.name, 'r') as f:
            assert f.read() != ''


@pytest.mark.parametrize("cmd", [
    lambda rep, rse: f'rucio-admin --legacy replicas set-tombstone {rep} --rse {rse}',
    lambda rep, rse: f'rucio replica remove {rep} --rse {rse}'
], ids=['legacy', 'current'])
@pytest.mark.noparallel(reason='Replica locked when run in parallel')
@pytest.mark.dirty(reason='Leaves replicas')
def test_set_tombstone(cmd, rse_factory, mock_scope, rucio_client):
    """ CLIENT(ADMIN): set a tombstone on a replica. """
    scope = mock_scope.external
    rse, _ = rse_factory.make_posix_rse()
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
    exitcode, out, err = execute(cmd(f'{scope}:{name}', rse))
    print(out, err)
    assert exitcode == 0
    assert 'Set tombstone successfully' in err

    # Set tombstone on locked replica
    rse, _ = rse_factory.make_posix_rse()
    rucio_client.add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
    exitcode, out, err = execute(cmd(f'{scope}:{name}', rse))
    assert exitcode != 0
    assert re.search('Replica is locked', err) is not None

    # Set tombstone on not found replica
    name = generate_uuid()
    exitcode, out, err = execute(cmd(f'{scope}:{name}', rse))
    assert exitcode != 0
    assert re.search('Replica not found', err) is not None


@pytest.mark.parametrize("cmd", [
    lambda a: f'rucio --legacy list-account-limits {a}',
    lambda a: f'rucio account limit list {a}'
], ids=['legacy', 'current'])
def test_list_account_limits(cmd, rse_factory, rucio_client, random_account):
    """ CLIENT (USER): list account limits. """
    random_account = random_account.external
    rse, _ = rse_factory.make_posix_rse()
    rse_exp = f'MOCK3|{rse}'

    local_limit = 10
    global_limit = 20
    rucio_client.set_local_account_limit(random_account, rse, local_limit)
    rucio_client.set_global_account_limit(random_account, rse_exp, global_limit)

    exitcode, out, err = execute(cmd(random_account))
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{local_limit}.*', out) is not None
    assert re.search(f'.*{rse_exp}.*{global_limit}.*', out) is not None

    exitcode, out, err = execute(f"{cmd(random_account)} --rse {rse}")
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{local_limit}.*', out) is not None
    assert re.search(f'.*{rse_exp}.*{global_limit}.*', out) is not None


@pytest.mark.parametrize("cmd", [
    lambda a: f'rucio --legacy list-account-usage {a}',
    lambda a: f'rucio account limit list {a}'
], ids=['legacy', 'current'])
@pytest.mark.noparallel(reason='modifies account limit on pre-defined RSE')
@pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'client', reason='uses abacus daemon and core functions')
def test_list_account_usage(cmd, rse_factory, rucio_client, random_account):
    """ CLIENT (USER): list account usage. """
    from rucio.core.account_counter import increase
    from rucio.daemons.abacus import account as abacus_account

    rse, rse_id = rse_factory.make_posix_rse()
    rse_expression = f'MOCK|{rse}'

    usage = 4
    local_limit = 10
    local_left = local_limit - usage
    global_limit = 20
    global_left = global_limit - usage

    rucio_client.set_local_account_limit(random_account.external, rse, local_limit)
    rucio_client.set_global_account_limit(random_account.external, rse_expression, global_limit)
    with db_session(DatabaseOperationType.WRITE) as session:
        increase(rse_id, random_account, 1, usage, session=session)
    abacus_account.run(once=True)
    exitcode, out, err = execute(cmd(random_account))
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{usage}.*{local_limit}.*{local_left}', out) is not None
    assert re.search(f'.*MOCK|{rse}.*{usage}.*{global_limit}.*{global_left}', out) is not None

    exitcode, out, err = execute(f"{cmd(random_account)} --rse {rse}")
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{usage}.*{local_limit}.*{local_left}', out) is not None
    assert re.search(f'.*MOCK|{rse}.*{usage}.*{global_limit}.*{global_left}', out) is not None


@pytest.mark.parametrize("set_cmd,del_cmd", [
    (lambda r, n, v: f'rucio-admin --legacy rse set-limit {r} {n} {v}', lambda r, n: f'rucio-admin --legacy rse delete-limit {r} {n}'),
    (lambda r, n, v: f'rucio rse limit add {r} --limit {n} {v}', lambda r, n: f'rucio rse limit remove {r} --limit {n}')
], ids=['legacy', 'current'])
def test_get_set_delete_limits_rse(set_cmd, del_cmd, rse_factory, rucio_client):
    """CLIENT(ADMIN): Get, set and delete RSE limits"""
    rse, _ = rse_factory.make_posix_rse()

    name = generate_uuid()
    value = random.randint(0, 100000)
    name2 = generate_uuid()
    value2 = random.randint(0, 100000)
    name3 = generate_uuid()

    exitcode, _, err = execute(set_cmd(rse, name, value))
    assert exitcode == 0

    exitcode, _, _ = execute(set_cmd(rse, name2, value2))
    assert exitcode == 0

    limit = rucio_client.get_rse_limits(rse)
    assert limit[name] == value
    assert limit[name2] == value2

    new_value = random.randint(100001, 999999999)
    execute(set_cmd(rse, name, new_value))
    limit = rucio_client.get_rse_limits(rse)
    assert limit[name] == new_value

    exitcode, _, _ = execute(del_cmd(rse, name))
    assert exitcode == 0
    limit = rucio_client.get_rse_limits(rse)
    assert name not in limit
    assert name2 in limit

    exitcode, out, err = execute(del_cmd(rse, name))
    assert f'Limit {name} not defined in RSE {rse}' in err

    non_integer = "NotAnInteger"
    exitcode, out, err = execute(set_cmd(rse, name, non_integer))
    assert 'The RSE limit value must be an integer' in err
    limits = rucio_client.get_rse_limits(rse)
    assert name3 not in limits


# Upload Tests
def test_upload(rse_factory, mock_scope, file_factory, rucio_client):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    """CLIENT(USER): Upload file"""
    # Verify argument logic
    cmd = f'rucio upload --rse {rse} --scope {scope}'
    exitcode, out, err = execute(cmd)
    assert "No files could be extracted from the given arguments" in err
    # TODO Should fail with exitcode != 0

    # Upload with scope
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file)

    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err
    files = [f for f in rucio_client.list_files(scope, name, long=True)]
    assert len(files) == 1
    assert files[0]['name'] == name


def test_upload_create_dataset(rse_factory, mock_scope, file_factory, rucio_client):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    dataset = f"{scope}:Dset{generate_uuid()}"
    # Upload with dataset
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file)
    cmd = f'rucio upload --rse {rse} --scope {scope} {tmp_file} {dataset}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err
    files = [f for f in rucio_client.list_files(scope, dataset.split(':')[1])]
    assert len(files) == 1
    assert files[0]['name'] == name.split('/')[-1]


def test_upload_with_lifetime(rse_factory, mock_scope, file_factory, rucio_client):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    # Verify expiration date logic
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file)

    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} '\
        '--expiration-date 2021-10-10-20:00:00 ' \
        f'--lifetime 20000  {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert "--lifetime and --expiration-date cannot be specified at the same time." in err

    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} '\
        f'--expiration-date 2021----10-10-20:00:00 {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert "does not match format '%Y-%m-%d-%H:%M:%S'" in err

    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} '\
        f'--expiration-date 2021-10-10-20:00:00  {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert "The specified expiration date should be in the future!" in err

    name = tmp_file.name.split('/')[-1]
    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} '\
        f'--expiration-date 2100-10-10-20:00:00 {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err
    files = [f for f in rucio_client.list_files(scope, name, long=True)]
    assert len(files) == 1
    assert files[0]['name'] == name


def test_upload_with_guid(rse_factory, mock_scope):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    # Upload with GUID
    with tempfile.NamedTemporaryFile() as tmp_file:
        cmd = 'rucio upload '\
            f'--rse {rse} --scope {scope} '\
            f'--guid {generate_uuid()} {tmp_file.name}'

        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert f"Successfully uploaded file {tmp_file.name.split('/')[-1]}" in err


def test_upload_with_pfn(rse_factory, mock_scope, file_factory,  vo):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    # Upload with PFN

    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file.name)

    file_md5 = md5(tmp_file)
    filesize = os.stat(tmp_file).st_size
    lfn = {'name': name, 'scope': scope, 'bytes': filesize, 'md5': file_md5}
    # user uploads file
    rse_settings = rsemgr.get_rse_info(rse=rse, vo=vo)
    protocol = rsemgr.create_protocol(rse_settings, 'write')
    protocol.connect()
    pfn = list(protocol.lfns2pfns(lfn).values())[0]

    # Fails automatically - cannot use --recursive with PFN
    cmd = 'rucio upload --recursive '\
        f'--rse {rse} --scope {scope} '\
        f'--pfn {pfn} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert "If PFN is specified, you cannot use --recursive" in err

    # Correctly upload with PFN
    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} '\
        f'--pfn {pfn} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err


def test_upload_with_impl(rse_factory, mock_scope, file_factory, rucio_client):
    ""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    impl = 'posix'

    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file.name)
    pfn = generate_uuid()
    cmd = f'rucio upload --legacy --rse {rse} --scope {scope} --impl {impl} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err

    # Fails to upload bc the PFN does is not a posix pfn
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file.name)
    pfn = generate_uuid()
    cmd = f'rucio upload --legacy --rse {rse} --scope {scope} --pfn {pfn} --impl {impl} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "Ignoring --impl option because --pfn option given" in err
    assert "RSE does not support requested protocol" in err

    # Do not get the error with just a impl
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file.name)
    cmd = f'rucio upload --legacy --rse {rse} --scope {scope} --impl {impl} {tmp_file}'
    # TODO: get list of all impls - fail in new CLI because posix is not a given choice
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err
    assert "WARNING: Ignoring --impl option because --pfn option given" not in err
    files = [f for f in rucio_client.list_files(scope, name, long=True)]
    assert len(files) == 1
    assert files[0]['name'] == name


# Download Tests
def test_download(did_factory, rse_factory, mock_scope):
    """CLIENT(USER): Rucio download"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    tmp_file1 = did_factory.upload_test_file(rse_name=rse, scope=scope)
    tmp_file2 = did_factory.upload_test_file(rse_name=rse, scope=scope)
    tmp_file3 = did_factory.upload_test_file(rse_name=rse, scope=scope)

    tmp_file1 = tmp_file1['name']
    tmp_file2 = tmp_file2['name']
    tmp_file3 = tmp_file3['name']

    with tempfile.TemporaryDirectory() as tmp_dir:
        # download files
        cmd = f'rucio download --legacy --dir {tmp_dir} {scope}:{tmp_file1}'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert tmp_file1 in os.listdir(f"{tmp_dir}/{scope}")

        # Use wildcard to download file
        cmd = f'rucio download --legacy --dir {tmp_dir} {scope}:{tmp_file2[:-3]}*'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert tmp_file2 in os.listdir(f"{tmp_dir}/{scope}")

        cmd = f"rucio -v download --legacy --dir {tmp_dir} --scope {scope} {tmp_file3}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert tmp_file3 in os.listdir(f"{tmp_dir}/{scope}")


def test_download_with_filter(did_factory, rse_factory, mock_scope, rucio_client):
    rse, _ = rse_factory.make_posix_rse()

    tmp_file1 = did_factory.upload_test_file(rse_name=rse, scope=mock_scope)
    tmp_file2 = did_factory.upload_test_file(rse_name=rse, scope=mock_scope)
    scope = mock_scope.external

    with tempfile.TemporaryDirectory() as tmp_dir:

        wrong_guid = generate_uuid()
        cmd = f'rucio download --legacy --dir {tmp_dir} --filter guid={wrong_guid} {scope}:*'
        exitcode, out, err = execute(cmd)
        assert exitcode != 0
        assert not os.path.exists(f"{tmp_dir}/{scope}/{tmp_file1['name']}")

        uuid = rucio_client.get_metadata(scope=scope, name=tmp_file1['name'])['guid']
        cmd = f"rucio download --legacy --dir {tmp_dir} --filter guid={uuid} {scope}:*"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file1['name']}")

        # Only use filter option to download file
        wrong_guid = generate_uuid()
        cmd = f'rucio download --legacy --dir {tmp_dir} --scope {scope} --filter guid={wrong_guid}'
        exitcode, out, err = execute(cmd)
        assert exitcode != 0
        assert not os.path.exists(f"{tmp_dir}/{scope}/{tmp_file2['name']}")

        uuid = rucio_client.get_metadata(scope=scope, name=tmp_file2['name'])['guid']
        cmd = f"rucio download --legacy --dir {tmp_dir} --scope {scope} --filter guid={uuid}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file2['name']}")


def test_download_timeout_options_accepted(rse_factory, mock_scope, did_factory):
    """CLIENT(USER): Rucio download timeout options """
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    tmp_file = did_factory.upload_test_file(rse_name=rse, scope=mock_scope)['name']
    with tempfile.TemporaryDirectory() as tmp_dir:

        cmd = f'rucio download --legacy --dir {tmp_dir} --transfer-timeout 3 --transfer-speed-timeout 1000 {scope}:{tmp_file}'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'successfully downloaded' in err
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file}")

    # Check that PFN the transfer-speed-timeout option is not accepted for --pfn
    cmd = f'rucio download --legacy --rse {rse} --transfer-speed-timeout 1 --pfn http://a.b.c/ {scope}:{tmp_file}'
    exitcode, out, err = execute(cmd)
    assert "Download with --pfn doesn't support --transfer-speed-timeout" in err
    assert exitcode != 0


def test_download_metalink(rse_factory, mock_scope, did_factory, rucio_client):
    """CLIENT(USER): Rucio download with metalink file"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    tmp_file = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    # Use filter and metalink option
    cmd = 'rucio download --legacy --scope mock --filter size=1 --metalink=test'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert 'Arguments filter and metalink cannot be used together' in err

    # Use did and metalink option
    cmd = 'rucio download --legacy --metalink=test mock:test'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert 'Arguments dids and metalink cannot be used together' in err

    # Download only with metalink file
    rse, _ = rse_factory.make_posix_rse()
    tmp_file = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']
    replica_file = rucio_client.list_replicas([{'scope': scope, 'name': tmp_file}], metalink=True)

    with tempfile.TemporaryDirectory() as tmp_dir:

        with tempfile.NamedTemporaryFile("w+", delete=False) as metalink_file:

            metalink_file.write(replica_file)
            metalink_file.close()

            cmd = f'rucio download --legacy --dir {tmp_dir} --metalink {metalink_file.name}'
            exitcode, out, err = execute(cmd)

            print(out, err)
            assert exitcode == 0
            assert f'{tmp_file} successfully downloaded' in err
            assert re.search('Total files.*1', out) is not None
            assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file}")


def test_download_with_impl(rse_factory, mock_scope, did_factory):
    """CLIENT(USER): Rucio download files with impl parameter assigned 'posix' value"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    tmp_file1 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']
    tmp_file3 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    impl = 'posix'

    with tempfile.TemporaryDirectory() as tmp_dir:

        # download files
        cmd = f'rucio download --legacy --dir {tmp_dir} {scope}:{tmp_file1} --impl {impl}'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file1}")

        # Use wildcard
        cmd = f'rucio download --legacy --dir {tmp_dir} --impl {impl} {scope}:{tmp_file3[:-5]}*'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file3}")


def test_download_pfns(rse_factory, mock_scope, did_factory, rucio_client):
    """CLIENT(USER): Rucio download files"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    name = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    replica_pfn = list(rucio_client.list_replicas([{'scope': scope, 'name': name}]))[0]['rses'][rse][0]

    # download files
    with tempfile.TemporaryDirectory() as download_dir:
        cmd = f'rucio download --legacy --dir {download_dir} --rse {rse} --pfn {replica_pfn} {scope}:{name}'
        exitcode, out, err = execute(cmd)
        assert re.search('Total files.*1', out) is not None
        assert exitcode == 0
        assert os.path.exists(f"{download_dir}/{scope}/{name}")

        # Try to use the --pfn without rse
        cmd = f"rucio -v download --legacy --dir {download_dir.rstrip('/')}/duplicate --pfn {replica_pfn} {scope}:{name}"
        exitcode, out, err = execute(cmd)
        assert "No RSE was given, selecting one." in err
        assert exitcode == 0
        assert re.search('Total files.*1', out) is not None
        assert os.path.exists(f"{download_dir.rstrip('/')}/duplicate/{scope}/{name}")

        # Download the pfn without an rse, except there is no RSE with that RSE
        non_existent_pfn = "http://fake.pfn.marker/"
        cmd = f"rucio -v download --legacy --dir {download_dir.rstrip('/')}/duplicate2 --pfn {non_existent_pfn} {scope}:{name}"
        exitcode, out, err = execute(cmd)
        assert "No RSE was given, selecting one." in err
        assert f"Could not find RSE for pfn {non_existent_pfn}" in err
        assert exitcode != 0
        assert not os.path.exists(f"{download_dir.rstrip('/')}/duplicate2/{scope}/{name}")


def test_download_file_check_by_size(rse_factory, mock_scope, did_factory):
    """CLIENT(USER): Rucio download files"""

    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    tmp_file1 = did_factory.upload_test_file(rse_name=rse, scope=scope)

    with tempfile.TemporaryDirectory() as tmp_dir:
        write_out = f"{tmp_dir}/{scope}"
        os.makedirs(write_out, exist_ok=True)
        with open(f"{write_out}/{tmp_file1['name']}", "w+") as f:
            f.write("dummy")

        # Download file
        cmd = f'rucio download --legacy --check-local-with-filesize-only --dir {tmp_dir} {scope}:{tmp_file1["name"]}'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "File with same name exists locally, but filesize mismatches" in err


@pytest.mark.parametrize(
    ("cli", "lfn"),
    [
        ("new", True),
        ("old", True),
        ("new", False),
        ("old", False),
    ]
)
def test_cli_declare_bad_replicas(cli, lfn, rse_factory, mock_scope, did_factory, tmp_path, rucio_client):
    """CLIENT(USER): Rucio declare bad replica"""
    log = logging.getLogger("bad-replicas")

    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    did = did_factory.upload_test_file(rse_name=rse, scope=scope)
    # replace scope object with scope name str
    did["scope"] = did["scope"].external

    cmd = []
    if cli == "new":
        cmd = ["rucio", "replica", "state", "update", "bad"]
    else:
        cmd = ["rucio-admin", "replicas", "declare-bad"]

    cmd.extend(["--reason", "test"])

    bad_replicas = []

    if lfn:
        lfn_path = tmp_path / "lfns.txt"
        lfn_path.write_text(did["name"] + "\n")

        if cli == "new":
            cmd.append("--lfn")
            bad_replicas.append(str(lfn_path))
        else:
            cmd.extend(["--lfns", str(lfn_path)])

        cmd.extend(["--rse", rse, "--scope", scope])
    else:
        bad_replicas.append(f"{did['scope']}:{did['name']}")

    cmd.extend(bad_replicas)
    cmd = shlex.join(cmd)

    code, stdout, stderr = execute(cmd)
    log.info("Command stdout:\n%s", stdout)
    log.warning("Command stderr:\n%s", stderr)
    assert code == 0, f"Running {cmd} failed. out:\n{stdout}\nerr\n{stderr}"

    replicas = next(rucio_client.list_replicas([did], rse_expression=rse, all_states=True))
    assert replicas["states"][rse] == "BAD"


def test_cli_declare_bad_replicas_invalid_usage():
    """CLIENT(USER): Rucio declare bad replica invalid argument handling"""
    base_cmd = ["rucio", "replica", "state", "update", "bad"]

    def run(expected_error, args=None, expected_code=1):
        args = args or []
        cmd = shlex.join(base_cmd + args)
        code, stdout, stderr = execute(cmd)

        assert code == expected_code, f"Running {cmd} did not fail as expected. out:\n{stdout}\nerr\n{stderr}"
        assert expected_error in stderr, f"Expected error message not found in stderr:\n{stderr}"

    run("Missing option '--reason'", expected_code=2)

    args = ["--reason", "test", "--lfn", "foo"]
    run("Scope and RSE are required", args=args, expected_code=1)

    args = ["--reason", "test", "--scope", "test", "--rse", "test", "--lfn", "foo", "bar"]
    run("Exactly one", args=args, expected_code=1)


def test_rse_qos_policy(rucio_client):
    mock_rse = "MOCK"
    policy = "SOMETHING_I_GUESS"

    cmd = f"rucio rse qos add {mock_rse} --policy {policy}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert policy in rucio_client.list_qos_policies(mock_rse)

    cmd = f"rucio rse qos list {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert policy in out

    cmd = f"rucio rse qos remove {mock_rse} --policy {policy}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert policy not in rucio_client.list_qos_policies(mock_rse)


def test_subscription(rucio_client, mock_scope, random_account, did_factory):
    subscription_name = generate_uuid()

    filter_ = json.dumps({})
    rules = [{"copies": 1, "rse_expression": "JDOE_DATADISK", "lifetime": 3600, "activity": "User Subscriptions"}]
    rules_json = json.dumps(rules)

    cmd = f"rucio subscription add {subscription_name} --account root --filter '{filter_}' --rule '{rules_json}'"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio subscription show {subscription_name} --account root"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert subscription_name in out

    # Ensure there is at least one DID for the test
    did_factory.make_dataset()
    did = [i for i in rucio_client.list_dids(mock_scope.external, filters=[{}], did_type="all")][0]
    cmd = f"rucio subscription touch {mock_scope.external}:{did}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    filter_ = json.dumps({"did_type": "all"})
    rule = json.dumps({})
    cmd = f"rucio subscription update {subscription_name} --filter '{filter_}' --rule {rule}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = 'rucio subscription list'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert subscription_name in out

    # Add a subscription for a specific account, ensure only that subscription is listed
    subscription_name_2 = generate_uuid()
    rucio_client.add_subscription(
            name=subscription_name_2,
            account=random_account.external,
            filter_={},
            replication_rules=rules,
            comments="test",
            lifetime=10,
            retroactive=False,
            dry_run=False,
    )

    cmd = f'rucio subscription list --account {random_account}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert subscription_name_2 in out
    assert subscription_name not in out


def test_did_metadata(rucio_client, root_account):
    scope = scope_name_generator()
    rucio_client.add_scope(account=root_account.external, scope=scope)
    dataset = file_generator().split("/")[-1]
    rucio_client.add_did(scope=scope, name=dataset, did_type="dataset")

    metadata_value = f"mock_{generate_uuid()[:15]}"
    cmd = f"rucio did metadata add {scope}:{dataset} --key project --value {metadata_value}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert metadata_value in [value for value in rucio_client.get_metadata(scope=scope, name=dataset).values()]

    cmd = f"rucio did metadata list {scope}:{dataset}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert metadata_value in out


@pytest.mark.dirty
def test_replica_state(mock_scope, rucio_client):
    mock_rse = "MOCK3"
    scope = mock_scope.external

    name1 = generate_uuid()
    rucio_client.add_replica(mock_rse, mock_scope.external, name1, 4, "deadbeef")

    cmd = f"rucio replica state update bad {scope}:{name1} --rse {mock_rse} --reason testing"
    exitcode, _, err = execute(cmd)
    print(err)
    assert exitcode == 0
    if "ERROR" in err:
        assert "Details: ERROR, multiple matches" in err  # The test rses are strange. I don't know why this happens.

    name2 = generate_uuid()
    rucio_client.add_replica(mock_rse, mock_scope.external, name2, 4, "deadbeef")
    cmd = f"rucio replica state update unavailable {mock_scope}:{name2} --rse {mock_rse}  --reason testing"
    exitcode, _, err = execute(cmd)

    name3 = generate_uuid()
    rucio_client.add_replica(mock_rse, mock_scope.external, name3, 4, "deadbeef")
    cmd = f"rucio replica state update quarantine {mock_scope}:{name3} --rse {mock_rse}"
    exitcode, _, err = execute(cmd)

    assert exitcode == 0
    assert "ERROR" not in err


def test_main_args():
    specify_account = "rucio --account root --auth-strategy userpass whoami"
    exitcode, out, err = execute(specify_account)
    assert exitcode == 0
    assert "root" in out

    specify_not_real_account = "rucio --account foo --auth-strategy userpass whoami"
    exitcode, out, err = execute(specify_not_real_account)
    assert exitcode == 1
    assert "CannotAuthenticate" in err

    legacy_arg = "rucio --legacy --account root --auth-strategy userpass whoami"
    exitcode, out, err = execute(legacy_arg)
    assert exitcode == 0
    assert "This method is being deprecated" in err
    assert "root" in out

    # Ensure non-exist commands don't throw the deprecation error
    non_existent_cmd = "rucio lfkdl --slkfdj 1"
    _, _, err = execute(non_existent_cmd)
    assert "This method is being deprecated" not in err


@pytest.mark.parametrize("cmd,warning,expected_exitcode", [
    ('rucio whoami', False, 0),
    ('rucio rse add', False, 2),  # rse add needs arguments
    ('rucio --legacy whoami', True, 0),
    ('rucio delete-rule', True, 1),  # delete-rule needs a rule ID
    ('rucio list-scopes', True, 1),
    ('rucio klfjgl', False, 1),
    ('rucio did fklgjdf', False, 1),
    ('rucio-admin --legacy --help', True, 0),
    ('rucio-admin --help', True, 1),
    ('rucio-admin --legacy rse add', True, 2),  # rse add needs arguments
    ('rucio-admin rse add', True, 1),
    ('rucio-admin sdkfjhds', True, 1)
], ids=[
    'Base command',
    "Failed command",
    "Base legacy command",
    "Failed legacy without flag",
    "Failed legacy command",
    "Non-existant command",
    "Non-existant subcommand",
    "Admin success with flag",
    "Admin success without flag",
    "Admin failure with flag",
    "Admin failure without flag",
    "Admin non-existant command"])
def test_deprecation_warning(cmd, warning, expected_exitcode):
    dep_warning = "is being deprecated"
    exitcode, out, err = execute(cmd)
    print(out, err)
    if warning:
        assert (dep_warning in err) or (dep_warning in out)
    else:
        assert (dep_warning not in err) or (dep_warning not in out)
    assert exitcode == expected_exitcode


@pytest.mark.noparallel(reason='Modifies the configuration file')
def test_passed_config():
    import configparser
    cfg = configparser.ConfigParser()
    cfg['database'] = {"default": "postgresql+psycopg://rucio:secret@ruciodb/rucio", "schema": ""}
    cfg["client"] = {"rucio_host": "", "auth_host": "", "auth_type": "", "username": "", "password": ""}

    # Set to a non-existent config path
    current_config = os.environ.get('RUCIO_CONFIG')
    fake_config = "/NoConfigHere.cfg"
    with open(fake_config, "w") as f:
        cfg.write(f)
    os.environ['RUCIO_CONFIG'] = fake_config
    exitcode, _, err = execute("rucio whoami")
    if current_config is not None:
        os.environ['RUCIO_CONFIG'] = current_config
    else:
        os.environ.pop("RUCIO_CONFIG")

    assert exitcode != 0
    assert "ERROR" in err


@pytest.mark.parametrize('cmd', ['ping', 'whoami', 'account', 'config', 'did', 'download', 'lifetime-exception', 'opendata', 'replica', 'rse', 'rule', 'scope', 'subscription', 'upload'])
def test_help_menus(cmd):
    """Verify help menus"""
    exitcode, out, err = execute("rucio --help")
    assert exitcode == 0
    assert "ERROR" not in err

    exitcode, out, err = execute(f"rucio {cmd} --help")
    assert exitcode == 0, f"Command {cmd} --help failed"  # Included for debugging purposes

    exitcode, out, err = execute(f"rucio {cmd} -h")
    assert exitcode == 0, f"Command {cmd} -h failed"

    # test the subcommands/operations as well
    out = out.split("\n")

    subcommands = [cmd.split(" ") for cmd in out[out.index("Commands:")+1:] if len(cmd) > 3]
    subcommands = [cmd[2] for cmd in subcommands]
    for subcommand in subcommands:
        menu = f"rucio {cmd} {subcommand} --help"
        exitcode, out, err = execute(menu)
        assert exitcode == 0, f"Command {menu} failed"  # Included for debugging purposes
