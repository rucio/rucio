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

import logging
import os
import random
import re
import shlex
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Union

import pytest
from click.testing import CliRunner

from rucio.cli.command import main as rucio_cli
from rucio.common.checksum import md5
from rucio.common.utils import generate_uuid, render_json
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import account_name_generator, execute, rse_name_generator, scope_name_generator


def _run_command(args: Union[str, list[str]]) -> tuple[int, str]:
    # Helper utility when the test result is not dependent on the stderr
    # Do not include "rucio" in the args, it is supplied by the runner.
    if isinstance(args, str):
        args = args.split(" ")
    print(args)
    result = CliRunner().invoke(rucio_cli, args)
    return result.exit_code, result.output


def test_rucio_version():
    """CLIENT(USER): Rucio version"""
    from rucio.version import version_string
    exitcode, out = _run_command("--version")
    assert exitcode == 0
    assert version_string() in out


def test_rucio_ping(rucio_client):
    """CLIENT(USER): Rucio ping"""
    from rucio.version import version_string
    exitcode, out = _run_command(f'--hostname {rucio_client.host} ping')
    assert exitcode == 0
    assert version_string() in out


def test_rucio_config_arg():
    """CLIENT(USER): Rucio config argument"""
    cmd = 'rucio --config errconfig ping'
    exitcode, _, err = execute(cmd)
    assert 'Could not load Rucio configuration file' in err and re.match('.*errconfig.*$', err, re.DOTALL)
    assert exitcode == 1


@pytest.mark.dirty(reason="Creates a new account on vo=def")
def test_add_account():
    """CLIENT(ADMIN): Add account"""
    tmp_val = account_name_generator()
    cmd = ["account", "add", tmp_val, "USER"]
    exitcode, out = _run_command(cmd)
    assert f'Added new account: {tmp_val}\n' in out
    assert exitcode == 0


@pytest.mark.dirty(reason="Creates new accounts on vo=def")
def test_list_account(random_account_factory):
    """CLIENT(ADMIN): List accounts"""
    n_accounts = 5
    tmp_accounts = [random_account_factory().external for _ in range(n_accounts)]
    for account in tmp_accounts:
        _run_command(f'account attribute set {account} --key test_list_account --value true')

    _, out = _run_command(["account", "list"])
    assert tmp_accounts[0] in out
    assert tmp_accounts[-1] in out  # Test by induction

    cmd = "account list --filter test_list_account=true"
    _, out = _run_command(cmd)
    assert set([o for o in out.split("\n") if o != '']) == set(tmp_accounts)  # There's a little '' printed after

    cmd = "account list --filter test_list_account=true --csv"
    _, out = _run_command(cmd)
    assert set(o.rstrip('\n') for o in out.split(',')) == set(tmp_accounts)  # Last obj in list has a `\n` included


def test_whoami():
    """CLIENT(USER): Rucio whoami"""
    exitcode, out = _run_command(['whoami'])
    assert 'account' in out
    assert exitcode == 0


def test_identity(random_account, rucio_client):
    """CLIENT(ADMIN): Add/list/delete identity"""

    cmd = f'account identity add {random_account} --type GSS --id jdoe@CERN.CH --email jdoe@CERN.CH'
    exitcode, out = _run_command(cmd)
    assert f'Added new identity to account: jdoe@CERN.CH-{random_account}\n' in out

    cmd = f'account identity list {random_account}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert 'jdoe@CERN.CH' in out

    cmd = f'account identity remove {random_account} --type GSS --id jdoe@CERN.CH'
    exitcode, out = _run_command(cmd)
    assert 'Deleted identity: jdoe@CERN.CH\n' in out

    cmd = f'account identity remove {random_account}'
    exitcode, out = _run_command(cmd)
    assert 'jdoe@CERN.CH' not in out

    # testing OIDC IDs

    id = "CN=Joe Doe,CN=707658,CN=jdoe,OU=Users,OU=Organic Units,DC=cern,DC=ch"
    cmd = f'rucio account identity add {random_account} --type OIDC --id "{id}" --email jdoe@CERN.CH'
    exitcode, out, _ = execute(cmd)
    assert exitcode == 0
    assert f'Added new identity to account: {id}-{random_account}\n' in out

    cmd = f'rucio account identity remove {random_account} --type OIDC --id "{id}"'
    exitcode, _, _ = execute(cmd)
    assert exitcode == 0

    ids = [i['type'] for i in rucio_client.list_identities(account=random_account.external)]
    assert 'OIDC' not in ids


def test_attributes(random_account):
    """CLIENT(ADMIN): Add/List/Delete attributes"""

    cmd = f'rucio account attribute set {random_account} --key test_attribute_key --value true'
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    # list attributes
    cmd = f'rucio account attribute list {random_account}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert 'test_attribute_key' in out

    # delete attribute to the account
    cmd = f'rucio account attribute unset {random_account} --key test_attribute_key'
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err


@pytest.mark.dirty(reason="Creates a new scope on vo=def")
def test_scope(random_account):
    """CLIENT(ADMIN): Add/list/delete/list scope"""
    tmp_scp = scope_name_generator()
    cmd = f'scope add --account {random_account} {tmp_scp}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert f'Added new scope to {random_account}: {tmp_scp}' in out

    cmd = f'scope list --account {random_account}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert tmp_scp in out

    cmd = f"rucio scope list --csv --account {random_account}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert tmp_scp in out.split('\n')

    cmd = 'scope list'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert tmp_scp in out


@pytest.mark.dirty(reason="RSEs are not deleted after the test")
def test_add_rse(rucio_client):
    """CLIENT(ADMIN): Add RSE"""
    tmp_val = rse_name_generator()
    cmd = f'rse add {tmp_val}'
    _, out = _run_command(cmd)
    assert f'Added new deterministic RSE: {tmp_val}\n' in out

    rses = [rse for rse in rucio_client.list_rses()]
    assert tmp_val in [rse['rse'] for rse in rses]
    assert [rse for rse in rses if rse['rse'] == tmp_val][0]['deterministic'] is True


@pytest.mark.dirty(reason="RSEs are not deleted after the test")
def test_add_rse_nondet(rucio_client):
    """CLIENT(ADMIN): Add non-deterministic RSE"""
    tmp_val = rse_name_generator()
    cmd = f'rse add --non-deterministic {tmp_val}'
    _, out = _run_command(cmd)
    assert f'Added new non-deterministic RSE: {tmp_val}\n' in out

    rses = [rse for rse in rucio_client.list_rses()]
    assert tmp_val in [rse['rse'] for rse in rses]
    assert [rse for rse in rses if rse['rse'] == tmp_val][0]['deterministic'] is False


def test_list_rses(rse_factory):
    """CLIENT(USER/ADMIN): List RSEs"""
    # TODO Test filter
    rse, _ = rse_factory.make_posix_rse()
    cmd = 'rse list'
    exitcode, out = _run_command(cmd)
    assert rse in out

    # Expected output is a new RSE on each line
    cmd = 'rse list --csv'
    _, out = _run_command(cmd)
    assert rse in out.split('\n')


def test_rse_add_distance(rse_factory):
    """CLIENT (ADMIN): Add distance to RSE"""
    # add RSEs
    rse_name_1, _ = rse_factory.make_posix_rse()
    rse_name_2, _ = rse_factory.make_posix_rse()

    # add distance between the RSEs
    cmd = f'rse distance set --distance 1 {rse_name_1} {rse_name_2}'
    exitcode, _ = _run_command(cmd)
    assert exitcode == 0

    cmd = f'rse distance set --distance 1 {rse_name_2} {rse_name_1}'
    exitcode, _ = _run_command(cmd)
    assert exitcode == 0


def test_rse_delete_distance(rse_factory, rucio_client):
    """CLIENT (ADMIN): Delete distance to RSE"""
    # add RSEs
    rse_name_1, _ = rse_factory.make_posix_rse()
    rse_name_2, _ = rse_factory.make_posix_rse()

    # add distance between the RSEs
    rucio_client.add_distance(rse_name_1, rse_name_2, distance=1)

    # delete distance OK
    cmd = f'rse distance unset {rse_name_1} {rse_name_2}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert f"Deleted distance from {rse_name_1} -> {rse_name_2}" in out

    # delete distance RSE not found
    cmd = f'rucio rse distance unset {rse_name_1} {generate_uuid()}'
    exitcode, out, err = execute(cmd)
    assert 'RSE does not exist.' in err


def test_create_dataset(rucio_client, mock_scope):
    """CLIENT(USER): Rucio add dataset"""
    scope = mock_scope.external
    tmp_name = f"{scope}:DSet_{generate_uuid()}"
    cmd = f'did add --type dataset {tmp_name}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert re.search('Added ' + tmp_name, out) is not None
    assert tmp_name in [f"{scope}:{did}" for did in rucio_client.list_dids(scope=scope, did_type="dataset", filters={})]


def test_add_files_to_dataset(rucio_client, rse_factory, mock_scope, did_factory):
    """CLIENT(USER): Rucio add files to dataset"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    temp_dataset = did_factory.make_dataset(scope=scope)
    temp_dataset_name = f"{scope}:{temp_dataset['name']}"
    # Files need to be registered on an RSE to be attached to a DID
    temp_file1 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']
    temp_file2 = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    # add files to dataset
    cmd = f'did content add --to-did {temp_dataset_name} {scope}:{temp_file1} {scope}:{temp_file2}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0

    names = [d['name'] for d in rucio_client.list_content(scope, temp_dataset['name'])]
    # find the added files
    assert temp_file1 in names
    assert temp_file2 in names


def test_detach_files_dataset(rucio_client, rse_factory, did_factory):
    """CLIENT(USER): Rucio detach files to dataset"""
    rse, _ = rse_factory.make_posix_rse()
    temp_dataset = did_factory.upload_test_dataset(rse, nb_files=3)
    scope = temp_dataset[0]['dataset_scope']
    temp_dataset_name = f"{scope}:{temp_dataset[0]['dataset_name']}"
    temp_file1 = temp_dataset[0]['did_name']
    temp_file2 = temp_dataset[1]['did_name']
    temp_file3 = temp_dataset[2]['did_name']

    cmd = f'did content remove --from-did {temp_dataset_name} {scope}:{temp_file2} {scope}:{temp_file3}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0

    # searching for the file in the new dataset
    names = [d['name'] for d in rucio_client.list_content(scope, temp_dataset[0]['dataset_name'])]
    # find the added files
    assert temp_file1 in names  # First file in the dataset
    # The second two are not
    assert temp_file2 not in names
    assert temp_file3 not in names


def test_attach_file_twice(rse_factory, did_factory, mock_scope):
    """CLIENT(USER): Rucio attach a file twice"""
    # Attach files to a dataset using the attach method
    rse, _ = rse_factory.make_posix_rse()
    temp_dataset = did_factory.upload_test_dataset(rse_name=rse, size=1, nb_files=1)
    scope = temp_dataset[0]['dataset_scope']
    temp_dataset_name = f"{scope}:{temp_dataset[0]['dataset_name']}"
    temp_file1 = temp_dataset[0]['did_name']

    # attach the files to the dataset
    cmd = f'rucio did content add --to-did {temp_dataset_name} {scope}:{temp_file1}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert re.search("The file already exists", err) is not None


def test_attach_dataset_twice(did_factory, mock_scope, rucio_client):
    """ CLIENT(USER): Rucio attach a dataset twice """
    scope = mock_scope.external
    container = did_factory.make_container(scope=mock_scope)['name']
    dataset = did_factory.make_dataset(scope=mock_scope)['name']

    # Attach dataset to container
    cmd = f'did content add --to-did {scope}:{container} {scope}:{dataset}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0

    # Attach again
    exitcode, out, err = execute("rucio " + cmd)
    assert exitcode != 0
    assert re.search("Data identifier already added to the destination content", err) is not None

    # This restraint does not apply to batched mode
    n_dids = 1400
    dids = [{'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'} for _ in range(0, n_dids)]
    rucio_client.add_dids(dids)

    cmd = f'did content add --to-did {scope}:{container}'
    for did in dids:
        cmd += f' {mock_scope}:{did["name"]}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, container)]
    assert all([did['name'] in names for did in dids])

    # Second attach should not fail
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, container)]
    assert all([did['name'] in names for did in dids])

    # Adding a new one will not fail either
    new_did = {'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'}
    rucio_client.add_dids([new_did])
    dids.append(new_did)
    cmd = f'did content add --to-did {scope}:{container}'
    for did in dids:
        cmd += f' {mock_scope}:{did["name"]}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    names = [d['name'] for d in rucio_client.list_content(mock_scope.external, container)]
    assert new_did['name'] in names


def test_detach_non_existing_file(did_factory):
    """CLIENT(USER): Rucio detach a non existing file"""
    dataset = did_factory.make_dataset()
    scope = dataset['scope']
    name = dataset['name']
    cmd = f'rucio did content remove --from-did {scope}:{name} {scope}:file_ghost'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert re.search("Data identifier not found.", err) is not None


def test_list_blocklisted_replicas(rucio_client, rse_factory, did_factory):
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
    cmd = f'replica list file {temp_dataset_name}'
    exitcode, out = _run_command(cmd)
    assert rse in out

    # Blocklist the rse
    rucio_client.update_rse(rse, {"availability_read": False})

    # list-file-replicas should, by default, list replicas from blocklisted rses
    exitcode, out = _run_command(cmd)
    assert rse in out


def test_create_rule(did_factory, rse_factory, rucio_client):
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
    cmd = f"rucio rule add {temp_scope}:{temp_file_name} --copies {n_replicas} --rses 'spacetoken=ATLASSCRATCHDISK'"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    rule = out.split('\n')[-2]
    assert re.match(r'^\w+$', rule)

    # check if rule exist for the file
    cmd = f"rule list --did {temp_scope}:{temp_file_name}"
    exitcode, out, = _run_command(cmd)
    assert re.search(rule, out) is not None


def test_create_rule_delayed(rucio_client, rse_factory, did_factory):
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
    cmd = f"rule add --delay-injection asdsaf {temp_scope}:{temp_file_name} --copies 1 --rses 'spacetoken=ATLASRULEDELAYED'"
    exitcode, out = _run_command(cmd)
    assert exitcode == 1  # Fails due to error checking in click

    # Add a correct rule
    cmd = f"rucio rule add --delay-injection 3600 {temp_scope}:{temp_file_name} --copies 1 --rses 'spacetoken=ATLASRULEDELAYED'"
    exitcode, out, err = execute(cmd)
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


def test_delete_rule(did_factory, rse_factory, rucio_client):
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
        cmd = f"rule remove {rule['id']}"
        exitcode, out = _run_command(cmd)
        assert exitcode == 0, f"Failed deleting rule with ID {rule['id']}"

    # Check if the file is still on the original RSE
    replicas = rucio_client.list_replicas(dids=[temp_file1])
    rses = [rse for r in replicas for rse in r['rses'].keys()]
    assert base_rse in rses
    # Did not make it to the new RSE
    assert temp_rse not in rses


def test_delete_rule_purge_replicas(did_factory, rse_factory, rucio_client):
    """CLIENT(USER): Remove rule and purge replicas"""
    base_rse, _ = rse_factory.make_posix_rse()
    temp_file1 = did_factory.upload_test_file(rse_name=base_rse)
    temp_file1['scope'] = temp_file1['scope'].external

    # remove limit and set attributes
    account = rucio_client.whoami()['account']
    temp_rse, _ = rse_factory.make_posix_rse()
    rucio_client.set_local_account_limit(account, temp_rse, -1)

    # Add the rule
    rule_id = rucio_client.add_replication_rule(
        dids=[temp_file1],
        copies=1,
        rse_expression=temp_rse,
        purge_replicas=True
    )[0]

    rule = rucio_client.get_replication_rule(rule_id)
    assert rule['purge_replicas'] is True

    exit, out, err = execute(f"rucio rule remove {rule_id}")
    assert exit == 0
    assert "ERROR" not in err

    rule = rucio_client.get_replication_rule(rule_id)
    assert rule['purge_replicas'] is True


@pytest.mark.dirty(reason="Cleanup can fail to complete because of child rules in client tests")
def test_move_rule(did_factory, rse_factory, rucio_client):
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
    cmd = f"rucio rule move {rule_id} --rses {new_rule_expr}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    new_rule = out.split('\n')[-2]  # trimming new line character

    # Check for new rule
    rules = rucio_client.list_replication_rules(filters={'scope': temp_file1['scope'], 'name': temp_file_name})
    rule_ids = [rule['id'] for rule in rules]

    assert new_rule in rule_ids
    assert rule_id in rule_ids  # Does not delete the old rule when moved


def test_move_rule_with_arguments(rse_factory, did_factory, rucio_client):
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
        rucio_client.add_rse_attribute(temp_rse, 'spacetoken', 'ATLASARGSMOVERULE')

    # Add the rule
    [rule_id] = rucio_client.add_replication_rule(
        copies=3,
        rse_expression='spacetoken=ATLASARGSMOVERULE',
        dids=[temp_file1]
    )

    # move rule
    new_rule_expr = "spacetoken=ATLASARGSMOVERULE|spacetoken=ATLASSD"
    new_rule_source_replica_expression = "spacetoken=ATLASARGSMOVERULE|spacetoken=ATLASSD"
    cmd = f"rucio rule move {rule_id} --source-rses '{new_rule_source_replica_expression}' --rses '{new_rule_expr}'"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    new_rule_id = out.split('\n')[-2]  # trimming new line character

    # Verify rule was made
    rules = rucio_client.list_replication_rules(filters={'scope': temp_file1['scope'], 'name': temp_file_name})
    assert new_rule_id in [rule['id'] for rule in rules]

    # Verify new details are changed
    rule_info = rucio_client.get_replication_rule(new_rule_id)
    assert new_rule_source_replica_expression == rule_info["source_replica_expression"]


def test_list_did_recursive(did_factory, mock_scope, rucio_client):
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
    cmd = f'did list {scope}:{tmp_container_1["name"]} --recursive'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert tmp_container_1['name'] in out
    assert tmp_container_2['name'] in out
    assert tmp_container_3['name'] in out

    # Wildcards are not allowed to use with --recursive
    cmd = f'rucio did list {scope}:* --recursive'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert re.search("Option recursive cannot be used with wildcards", err) is not None


def test_attach_many_dids(mock_scope, did_factory, rucio_client):
    """ CLIENT(USER): Rucio attach many (>1000) DIDs to ensure batching is done correctly, checks the `--from-file` option """
    n_dids = 1400

    # Setup making the dids
    temp_dataset = did_factory.make_container(scope=mock_scope)
    temp_dataset_name = f"{mock_scope}:{temp_dataset['name']}"

    # Note: upload_test_dataset takes FAR too long (10+ minutes) to run for this number of dids - just add rucio_client attaching to the mock container
    dids = [{'name': f'dsn_{generate_uuid()}', 'scope': mock_scope, 'type': 'DATASET'} for _ in range(0, n_dids)]
    rucio_client.add_dids(dids)

    # Attaching over 1000 DIDs with CLI
    cmd = f'rucio attach {temp_dataset_name}'
    for did in dids:
        cmd += f' {mock_scope}:{did["name"]}'
    exitcode, out, err = execute(cmd)
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

        cmd = f'did content add {did_file.name} --to-did {temp_dataset_name} --from-file'
        exitcode, out = _run_command(cmd)
        assert exitcode == 0

        names = [d['name'] for d in rucio_client.list_content(mock_scope.external, temp_dataset['name'])]
        assert all([did['name'] in names for did in dids])


def test_attach_dids_from_file(rse_factory, mock_scope, did_factory, rucio_client):
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
        cmd = f'did content add --to-did {temp_dataset_name} -f {did_file.name}'
        exitcode, out = _run_command(cmd)

    assert exitcode == 0
    assert 'DIDs successfully attached' in out

    names = [d['name'] for d in rucio_client.list_content(scope, temp_dataset['name'])]
    assert len(names) == 3
    assert (temp_file1 in names) and (temp_file2 in names) and (temp_file3 in names)


def test_import_data(rse_factory, rucio_client):
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

        cmd = f'rucio data import {tmp_file.name}'
        exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    assert re.search('Data successfully imported', out) is not None

    updated_rses = [rse['rse'] for rse in rucio_client.list_rses("country_name=ATLASIMPORTDATA")]
    assert all([rse in updated_rses for rse in rses])


@pytest.mark.noparallel(reason='fails when run in parallel')
def test_export_data():
    """ CLIENT(ADMIN): Export data from rucio"""
    with tempfile.NamedTemporaryFile(suffix=".json") as tmp_file:

        cmd = f'rucio data export {tmp_file.name}'
        exitcode, out, err = execute(cmd)

        assert exitcode == 0
        assert 'Data successfully exported' in out
        assert os.path.exists(tmp_file.name)

        with open(tmp_file.name, 'r') as f:
            assert f.read() != ''


@pytest.mark.noparallel(reason='Replica locked when run in parallel')
@pytest.mark.dirty(reason='Leaves replicas')
def test_set_tombstone(rse_factory, mock_scope, rucio_client):
    """ CLIENT(ADMIN): set a tombstone on a replica. """
    scope = mock_scope.external
    rse, _ = rse_factory.make_posix_rse()
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, 'aaaaaaaa')
    cmd = f'rucio replica remove {scope}:{name} --rse {rse}'
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    assert 'Set tombstone successfully' in err

    # Set tombstone on locked replica
    rse, _ = rse_factory.make_posix_rse()
    rucio_client.add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
    cmd = f'rucio replica remove {scope}:{name} --rse {rse}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert re.search('Replica is locked', err) is not None

    # Set tombstone on not found replica
    name = generate_uuid()
    cmd = f'rucio replica remove {scope}:{name} --rse {rse}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert re.search('Replica not found', err) is not None


def test_list_account_limits(rse_factory, rucio_client, random_account):
    """ CLIENT (USER): list account limits. """
    random_account = random_account.external
    rse, _ = rse_factory.make_posix_rse()
    rse_exp = f'MOCK3|{rse}'

    local_limit = 10
    global_limit = 20
    rucio_client.set_local_account_limit(random_account, rse, local_limit)
    rucio_client.set_global_account_limit(random_account, rse_exp, global_limit)

    cmd = f'account limit list {random_account}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{local_limit}.*', out) is not None
    assert re.search(f'.*{rse_exp}.*{global_limit}.*', out) is not None

    cmd = f'account limit list --rse {rse} {random_account}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{local_limit}.*', out) is not None
    assert re.search(f'.*{rse_exp}.*{global_limit}.*', out) is not None


@pytest.mark.noparallel(reason='modifies account limit on pre-defined RSE')
@pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'client', reason='uses abacus daemon and core functions')
def test_list_account_usage(rse_factory, rucio_client, random_account):
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
    cmd = f'account limit list {random_account}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{usage}.*{local_limit}.*{local_left}', out) is not None
    assert re.search(f'.*MOCK|{rse}.*{usage}.*{global_limit}.*{global_left}', out) is not None

    cmd = f'account limit list --rse {rse} {random_account}'
    exitcode, out = _run_command(cmd)
    assert exitcode == 0
    assert re.search(f'.*{rse}.*{usage}.*{local_limit}.*{local_left}', out) is not None
    assert re.search(f'.*MOCK|{rse}.*{usage}.*{global_limit}.*{global_left}', out) is not None


def test_get_set_delete_limits_rse(rse_factory, rucio_client):
    """CLIENT(ADMIN): Get, set and delete RSE limits"""
    rse, _ = rse_factory.make_posix_rse()

    name = generate_uuid()
    value = random.randint(0, 100000)
    name2 = generate_uuid()
    value2 = random.randint(0, 100000)
    name3 = generate_uuid()

    cmd = f'rse limit set {rse} --limit {name} {value}'
    exitcode, _ = _run_command(cmd)
    assert exitcode == 0

    cmd = f'rse limit set {rse} --limit {name2} {value2}'
    exitcode, _, = _run_command(cmd)
    assert exitcode == 0

    limit = rucio_client.get_rse_limits(rse)
    assert limit[name] == value
    assert limit[name2] == value2

    new_value = random.randint(100001, 999999999)
    cmd = f'rse limit set {rse} --limit {name} {new_value}'
    _run_command(cmd)
    limit = rucio_client.get_rse_limits(rse)
    assert limit[name] == new_value

    cmd = f'rse limit unset {rse} --limit {name}'
    exitcode, _ = _run_command(cmd)
    assert exitcode == 0
    limit = rucio_client.get_rse_limits(rse)
    assert name not in limit
    assert name2 in limit

    cmd = f'rucio rse limit unset {rse} --limit {name}'
    exitcode, out, err = execute(cmd)
    assert f'Limit {name} not defined in RSE {rse}' in err

    non_integer = "NotAnInteger"
    cmd = f'rucio rse limit set {rse} --limit {name} {non_integer}'
    exitcode, out, err = execute(cmd)
    assert f"'{non_integer}' is not a valid integer" in err
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


def test_upload_with_guid(rse_factory, mock_scope, file_factory):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    # Upload with GUID, make sure the file is not empty to avoid UploadClient protocol-stat retry backoff
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file)
    cmd = 'rucio upload '\
        f'--rse {rse} --scope {scope} '\
        f'--guid {generate_uuid()} {tmp_file}'

    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err


def test_upload_with_pfn(rse_factory, mock_scope, file_factory, vo):
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
    cmd = f'rucio upload --rse {rse} --scope {scope} --impl {impl} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"Successfully uploaded file {name}" in err

    # Fails to upload bc the PFN does is not a posix pfn
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file.name)
    pfn = generate_uuid()
    cmd = f'rucio upload --rse {rse} --scope {scope} --pfn {pfn} --impl {impl} {tmp_file}'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "Ignoring --impl option because --pfn option given" in err
    assert "RSE does not support requested protocol" in err

    # Do not get the error with just a impl
    tmp_file = file_factory.file_generator()
    name = os.path.basename(tmp_file.name)
    cmd = f'rucio upload --rse {rse} --scope {scope} --impl {impl} {tmp_file}'
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
        cmd = f'download --dir {tmp_dir} {scope}:{tmp_file1}'
        exitcode, out = _run_command(cmd)
        assert exitcode == 0
        assert tmp_file1 in os.listdir(f"{tmp_dir}/{scope}")

        # Use wildcard to download file
        cmd = f'download --dir {tmp_dir} {scope}:{tmp_file2[:-3]}*'
        exitcode, out = _run_command(cmd)
        assert exitcode == 0
        assert tmp_file2 in os.listdir(f"{tmp_dir}/{scope}")

        cmd = f"download --dir {tmp_dir} --scope {scope} {tmp_file3}"
        exitcode, out = _run_command(cmd)
        assert exitcode == 0
        assert tmp_file3 in os.listdir(f"{tmp_dir}/{scope}")


def test_download_with_filter(did_factory, rse_factory, mock_scope, rucio_client):
    rse, _ = rse_factory.make_posix_rse()

    tmp_file1 = did_factory.upload_test_file(rse_name=rse, scope=mock_scope)
    tmp_file2 = did_factory.upload_test_file(rse_name=rse, scope=mock_scope)
    scope = mock_scope.external

    with tempfile.TemporaryDirectory() as tmp_dir:

        wrong_guid = generate_uuid()
        cmd = f'download --dir {tmp_dir} --filter guid={wrong_guid} {scope}:*'
        exitcode, out = _run_command(cmd)
        assert exitcode != 0
        assert not os.path.exists(f"{tmp_dir}/{scope}/{tmp_file1['name']}")

        uuid = rucio_client.get_metadata(scope=scope, name=tmp_file1['name'])['guid']
        cmd = f"download --dir {tmp_dir} --filter guid={uuid} {scope}:*"
        exitcode, out = _run_command(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file1['name']}")

        # Only use filter option to download file
        wrong_guid = generate_uuid()
        cmd = f'download --dir {tmp_dir} --scope {scope} --filter guid={wrong_guid}'
        exitcode, out = _run_command(cmd)
        assert exitcode != 0
        assert not os.path.exists(f"{tmp_dir}/{scope}/{tmp_file2['name']}")

        uuid = rucio_client.get_metadata(scope=scope, name=tmp_file2['name'])['guid']
        cmd = f"download --dir {tmp_dir} --scope {scope} --filter guid={uuid}"
        exitcode, out = _run_command(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file2['name']}")


def test_download_timeout_options_accepted(rse_factory, mock_scope, did_factory):
    """CLIENT(USER): Rucio download timeout options """
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    tmp_file = did_factory.upload_test_file(rse_name=rse, scope=mock_scope)['name']
    with tempfile.TemporaryDirectory() as tmp_dir:

        cmd = f'rucio download --dir {tmp_dir} --transfer-timeout 3 --transfer-speed-timeout 1000 {scope}:{tmp_file}'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert 'successfully downloaded' in err
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file}")

    # Check that PFN the transfer-speed-timeout option is not accepted for --pfn
    cmd = f'rucio download --rses {rse} --transfer-speed-timeout 1 --pfn http://a.b.c/ {scope}:{tmp_file}'
    exitcode, out, err = execute(cmd)
    assert "Download with --pfn doesn't support --transfer-speed-timeout" in err
    assert exitcode != 0


def test_download_metalink(rse_factory, mock_scope, did_factory, rucio_client):
    """CLIENT(USER): Rucio download with metalink file"""
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    tmp_file = did_factory.upload_test_file(rse_name=rse, scope=scope)['name']

    # Use filter and metalink option
    cmd = 'rucio download --scope mock --filter size=1 --metalink=test'
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert 'Arguments filter and metalink cannot be used together' in err

    # Use did and metalink option
    cmd = 'rucio download --metalink=test mock:test'
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

            cmd = f'rucio download --dir {tmp_dir} --metalink {metalink_file.name}'
            exitcode, out, err = execute(cmd)

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
        cmd = f'download --dir {tmp_dir} {scope}:{tmp_file1} --impl {impl}'
        exitcode, out = _run_command(cmd)
        assert exitcode == 0
        assert os.path.exists(f"{tmp_dir}/{scope}/{tmp_file1}")

        # Use wildcard
        cmd = f'download --dir {tmp_dir} --impl {impl} {scope}:{tmp_file3[:-5]}*'
        exitcode, out = _run_command(cmd)
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
        cmd = f'download --dir {download_dir} --rses {rse} --pfn {replica_pfn} {scope}:{name}'
        exitcode, out = _run_command(cmd)
        assert re.search('Total files.*1', out) is not None
        assert exitcode == 0
        assert os.path.exists(f"{download_dir}/{scope}/{name}")

        # Try to use the --pfn without rse
        cmd = f"rucio -v download --dir {download_dir.rstrip('/')}/duplicate --pfn {replica_pfn} {scope}:{name}"
        exitcode, out, err = execute(cmd)
        assert "No RSE was given, selecting one." in err
        assert exitcode == 0
        assert re.search('Total files.*1', out) is not None
        assert os.path.exists(f"{download_dir.rstrip('/')}/duplicate/{scope}/{name}")

        # Download the pfn without an rse, except there is no RSE with that RSE
        non_existent_pfn = "http://fake.pfn.marker/"
        cmd = f"rucio -v download --dir {download_dir.rstrip('/')}/duplicate2 --pfn {non_existent_pfn} {scope}:{name}"
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
        cmd = f'rucio download --check-local-with-filesize-only --dir {tmp_dir} {scope}:{tmp_file1["name"]}'
        exitcode, out, err = execute(cmd)
        assert exitcode == 0
        assert "File with same name exists locally, but filesize mismatches" in err


@pytest.mark.parametrize(("lfn"), [(True), (False)])
def test_cli_declare_bad_replicas(lfn, rse_factory, mock_scope, did_factory, tmp_path, rucio_client):
    """CLIENT(USER): Rucio declare bad replica"""
    log = logging.getLogger("bad-replicas")

    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external

    did = did_factory.upload_test_file(rse_name=rse, scope=scope)
    # replace scope object with scope name str
    did["scope"] = did["scope"].external

    cmd = ["rucio", "replica", "state", "update", "bad"]
    cmd.extend(["--reason", "test"])

    bad_replicas = []

    if lfn:
        lfn_path = tmp_path / "lfns.txt"
        lfn_path.write_text(did["name"] + "\n")

        cmd.append("--lfn")
        bad_replicas.append(str(lfn_path))

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
