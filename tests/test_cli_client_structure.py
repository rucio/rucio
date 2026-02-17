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
import os
import re
import tempfile
from typing import TYPE_CHECKING

import pytest

from rucio.common.exception import RucioException
from rucio.common.utils import generate_uuid
from rucio.tests.common import account_name_generator, execute, file_generator, rse_name_generator, scope_name_generator

if TYPE_CHECKING:
    from rucio.common.types import FileToUploadDict


@pytest.mark.noparallel(reason='Modifies the configuration file')
def test_main_args():
    specify_account = "rucio --account root --auth-strategy userpass whoami"
    exitcode, out, err = execute(specify_account)
    assert exitcode == 0
    assert "This method is being deprecated" not in err
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


def test_help_menus():
    """Verify help menus"""
    exitcode, out, err = execute("rucio --help")
    assert exitcode == 0
    assert "ERROR" not in err
    out = out.split("\n")
    commands = [cmd.split(" ") for cmd in out[out.index("Commands:") + 1:] if len(cmd) > 3]  # command has two spaces in front of it
    commands = [cmd[2] for cmd in commands]

    for command in commands:
        exitcode, out, err = execute(f"rucio {command} --help")
        assert exitcode == 0, f"Command {command} --help failed"  # Included for debugging purposes

        exitcode, out, err = execute(f"rucio {command} -h")
        assert exitcode == 0, f"Command {command} -h failed"

        # test the subcommands/operations as well
        out = out.split("\n")
        try:
            subcommands = [cmd.split(" ") for cmd in out[out.index("Commands:") + 1:] if len(cmd) > 3]
            subcommands = [cmd[2] for cmd in subcommands]
            for subcommand in subcommands:
                menu = f"rucio {command} {subcommand} --help"
                exitcode, out, err = execute(menu)
                assert exitcode == 0, f"Command {menu} failed"  # Included for debugging purposes

                menu = f"rucio {command} {subcommand} -h"
                exitcode, out, err = execute(menu)
                assert exitcode == 0, f"Command {menu} -h failed"

        except ValueError:  # "Commands:" not in list
            continue


def test_account(rucio_client):
    new_account = account_name_generator()
    command = f"rucio account add {new_account} USER"
    exitcode, _, err = execute(command)
    assert exitcode == 0
    assert "ERROR" not in err
    assert new_account in [account["account"] for account in rucio_client.list_accounts()]

    update_email = "jdoe@cern.ch"
    command = f"rucio account update {new_account} --email {update_email}"
    exitcode, _, err = execute(command)
    assert exitcode == 0
    assert "ERROR" not in err
    assert update_email == [account["email"] for account in rucio_client.list_accounts() if account["account"] == new_account][0]

    command = "rucio account list"
    exitcode, out, err = execute(command)
    assert exitcode == 0
    assert "ERROR" not in err
    assert new_account in out

    command = f"rucio account show {new_account}"
    exitcode, out, err = execute(command)
    assert exitcode == 0
    assert "ERROR" not in err
    assert new_account in out

    command = f"rucio account remove {new_account}"
    exitcode, out, err = execute(command)
    assert exitcode == 0
    assert "ERROR" not in err
    assert new_account not in [account["account"] for account in rucio_client.list_accounts()]

    # Test account banning
    tmp_account = account_name_generator()
    execute(f"rucio account add {tmp_account} USER")

    cmd = f"rucio account update {tmp_account} --ban"
    exitcode, _, new_ban_log = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in new_ban_log

    cmd = f"rucio account update {tmp_account} --unban"
    exitcode, _, new_unban_log = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in new_unban_log


def test_account_attribute(jdoe_account):
    fake_key = generate_uuid()[:15]
    cmd = f"rucio account attribute add {jdoe_account} --key test_{fake_key}_key --value True"
    exitcode, _, log = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in log

    cmd = f"rucio account attribute list {jdoe_account}"
    exitcode, out, err = execute(cmd)
    print(err)
    assert exitcode == 0
    assert "ERROR" not in err
    assert f"test_{fake_key}_key" in out

    cmd = f"rucio account attribute remove {jdoe_account} --key test_{fake_key}_key"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio -v account attribute list {jdoe_account}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert f"test_{fake_key}_key" not in out


def test_account_identities(rucio_client):
    tmp_account = account_name_generator()
    execute(f"rucio account add {tmp_account} USER")

    cmd = "rucio account identity list"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 2  # Error raised when account is not included

    cmd = f"rucio account identity list {tmp_account}"
    _, _, err = execute(cmd)
    assert "ERROR" not in err

    email = "anon@email.com"
    cmd = f"rucio account identity add {tmp_account} --type GSS --email {email} --id {email}"
    _, _, err = execute(cmd)
    assert "ERROR" not in err
    id = [account for account in rucio_client.list_identities(tmp_account) if account["type"] == "GSS"][0]
    assert id["email"] == email
    assert id["identity"] == email

    cmd = f"rucio account identity list {tmp_account}"
    _, out, err = execute(cmd)
    assert "ERROR" not in err
    assert email in out

    cmd = f"rucio account identity add --account {tmp_account} --type NotAType --email {email} --id {email}"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 1


def test_account_limit(jdoe_account, rucio_client):
    jdoe_account = jdoe_account.external
    mock_rse = "MOCK"

    bytes_limit = 10
    cmd = f"rucio account limit add {jdoe_account} --rse {mock_rse} --bytes {bytes_limit}"
    _, _, set_log = execute(cmd)
    assert "ERROR" not in set_log
    assert bytes_limit == rucio_client.get_account_limits(jdoe_account, mock_rse, locality="local")[mock_rse]

    cmd = f"rucio -v account limit list {jdoe_account} --rse {mock_rse}"
    _, out, err = execute(cmd)
    assert "ERROR" not in err
    assert mock_rse in out

    cmd = f"rucio account limit remove {jdoe_account} --rse {mock_rse}"
    _, _, rm_log = execute(cmd)
    assert "ERROR" not in rm_log
    assert rucio_client.get_account_limits(jdoe_account, mock_rse, locality="local")[mock_rse] is None

    cmd = f"rucio account limit add {jdoe_account} --rse {mock_rse} --bytes {bytes_limit} --locality NotAnOption"
    exitcode, _, _ = execute(cmd)
    assert exitcode == 1  # Fails bc locality is limited to local or global


@pytest.mark.noparallel("Changes config settings")
def test_config():
    cmd = "rucio config list"  # Basic - this command works
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    section = str(generate_uuid())
    option = "new_option"
    value = "new_value"

    cmd = f"rucio config add --section {section} --key {option} --value {value}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    # Verify you cannot "add" on top of a section that already exists
    cmd = f"rucio config add --section {section} --key {option} --value {value}"
    exitcode, _, err = execute(cmd)
    assert "ERROR" in err

    # But you can add a different option
    cmd = f"rucio config add --section {section} --key {section} --value {section}"
    exitcode, _, err = execute(cmd)
    assert "ERROR" not in err

    exitcode, out, err = execute(f"rucio config list --section {section} --key {option}")
    assert exitcode == 0
    assert "ERROR" not in err
    assert value in out

    cmd = f"rucio config remove --section {section} --key {option}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    exitcode, out, err = execute(f"rucio config list --section {section}")
    assert exitcode == 0
    assert "ERROR" not in err
    assert value not in out

    # Verify you can update
    section = str(generate_uuid())
    new_value = "newer_value"

    # Using `update` on a non-existent field is not allowed
    cmd = f"rucio config update --section {section} --key {option} --value {value}"
    exitcode, _, err = execute(cmd)
    assert "ERROR" in err

    # Re-adding to the existing option
    cmd = f"rucio config add --section {section} --key {option} --value {value}"
    exitcode, _, err = execute(cmd)
    assert "ERROR" not in err

    # Use update to change it to the new value
    cmd = f"rucio config update --section {section} --key {option} --value {new_value}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    exitcode, out, err = execute(f"rucio config list --section {section}")
    assert exitcode == 0
    assert new_value in out


@pytest.mark.parametrize("file_config_mock", [
    {"overrides": [('experimental', 'cli', 'tabulate')]},
    {"overrides": [('experimental', 'cli', 'rich')]},
], indirect=True)
def test_did(rucio_client, root_account, file_config_mock):
    scope = scope_name_generator()
    rucio_client.add_scope(account=root_account.external, scope=scope)
    dataset = file_generator().split("/")[-1]
    rucio_client.add_did(scope=scope, name=dataset, did_type="dataset")
    container = file_generator().split("/")[-1]
    rucio_client.add_did(scope=scope, name=container, did_type="container")

    cmd = f"rucio did list {scope}:*"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio did list {scope}:* --short"
    exitcode, stdout, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    lines = [line.strip() for line in stdout.split("\n") if line.strip()]
    pattern = re.compile(rf"^{scope}:.+$")
    assert all(pattern.match(line) for line in lines), f"All lines should follow the {scope}:name pattern"
    assert f"{scope}:{dataset}" in lines, f"Expected {scope}:{dataset} in list with short option"
    assert f"{scope}:{container}" in lines, f"Expected {scope}:{container} in list with short option"

    cmd = f"rucio did update --touch {scope}:{dataset}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio did list {scope}:* --filter type=all"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert f"{scope}:{dataset}" in out
    assert "ERROR" not in err

    cmd = f"rucio did show {scope}:{dataset}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dataset in out  # At least list the name properly

    # Add the collection DIDs
    scope = scope_name_generator()
    rucio_client.add_scope(account=root_account.external, scope=scope)
    dataset = file_generator().split("/")[-1]

    cmd = f"rucio did add --type container {scope}:{dataset}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dataset in [dataset for dataset in rucio_client.list_dids(scope=scope, filters=[], did_type="container")]

    scope = scope_name_generator()
    rucio_client.add_scope(account=root_account.external, scope=scope)
    dataset = file_generator().split("/")[-1]

    cmd = f"rucio did add --type dataset {scope}:{dataset}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dataset in [dataset for dataset in rucio_client.list_dids(scope=scope, filters=[], did_type="dataset")]


def test_did_content(root_account, rucio_client):
    scope = scope_name_generator()
    rucio_client.add_scope(account=root_account.external, scope=scope)
    dataset = file_generator().split("/")[-1]
    rucio_client.add_did(scope=scope, name=dataset, did_type="dataset")
    container = file_generator().split("/")[-1]
    rucio_client.add_did(scope=scope, name=container, did_type="container")

    cmd = f"rucio did content add {scope}:{dataset} --to-did {scope}:{container}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio did content list {scope}:{container}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dataset in out

    # Verify dids are required for list/history is enforced
    cmd = "rucio did content list"
    exitcode, out, err = execute(cmd)
    assert exitcode == 2

    cmd = "rucio did content history"
    exitcode, out, err = execute(cmd)
    assert exitcode == 2

    execute(f"rucio did content remove {scope}:{dataset} --from-did {scope}:{container}")

    cmd = f"rucio did content history {scope}:{container}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dataset in out

    cmd = f"rucio did update --close {scope}:{container}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    # Verify it has been closed
    cmd = f"rucio did content add {scope}:{dataset} --to-did {scope}:{container}"
    _, _, err = execute(cmd)
    assert "ERROR" in err

    cmd = f"rucio did update  --open {scope}:{container}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    # Verify is has been re-opened
    cmd = f"rucio did content add {scope}:{dataset} --to-did {scope}:{container}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio did list --parent {scope}:{dataset}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert container in out

    cmd = f"rucio did content remove {scope}:{dataset} --from-did {scope}:{container}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio did list --parent {scope}:{dataset}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert container not in out  # Only checks for output not err, upstream error with mistaking claim scopes dne


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

    # NOTE - This cannot be done in the current dataset - throws a notimplementederror
    # cmd = f"rucio -v did metadata remove --did {scope}:{dataset} --key project"
    # exitcode, _, err = execute(cmd)
    # print(err)
    # assert exitcode == 0
    # assert "ERROR" not in err
    # assert metadata_value not in [value for value in rucio_client.get_metadata(scope=scope, name=dataset).values()]


def test_upload_download():
    # DID upload/download not tested for implementation as their tests are identical to the base rucio bin versions
    cmd = "rucio upload there-is-not-a-file-here --rse mock"
    exitcode, _, _ = execute(cmd)
    assert exitcode != 2  # Failure is not due to the command structure

    cmd = "rucio download fake:fake --dir ."
    exitcode, _, _ = execute(cmd)
    assert exitcode != 2  # Failure is not due to the command structure


def test_lifetime_exception(rucio_client, mock_scope):
    from rucio.client.uploadclient import UploadClient

    input_file = tempfile.NamedTemporaryFile()
    mock_did = tempfile.NamedTemporaryFile()
    mock_rse = "MOCK-POSIX"
    upload_client = UploadClient(rucio_client)

    item: FileToUploadDict = {
        'path': mock_did.name,
        'rse': mock_rse,
        'did_scope': mock_scope.external,
    }

    upload_client.upload(items=[item])

    with open(input_file.name, "w") as f:
        f.write(f"{mock_scope}:{mock_did.name.split('/')[-1]}")

    cmd = f"rucio lifetime-exception add -f {input_file.name} --reason mock_test -x 2100-12-30"
    exitcode, _, err = execute(cmd)
    print(err)
    assert exitcode == 0
    if "ERROR" not in err:
        assert "not affected by the lifetime model" in err
    else:
        assert "Nothing to submit" in err


@pytest.mark.dirty
def test_replica(mock_scope, rucio_client, did_factory, rse_factory):
    mock_did = tempfile.NamedTemporaryFile()
    mock_rse, _ = rse_factory.make_posix_rse()

    scope = mock_scope.external
    name = mock_did.name.split("/")[-1]

    rucio_client.add_replica(mock_rse, scope, name, 1, "deadbeef")  # I don't know why this is the default adler32

    cmd = f"rucio replica list dataset {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" not in err
    assert exitcode == 0
    assert name not in out

    cmd = f"rucio replica list file {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" not in err
    assert exitcode == 0
    assert name in out

    cmd = f"rucio replica list file {scope}:{name} --pfns --rses {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert "ERROR" not in err
    assert exitcode == 0
    pfn = [r for r in rucio_client.list_replicas([{"name": name, "scope": scope}])][0]["pfns"].keys()
    pfn = list(pfn)[0]
    assert pfn in out

    cmd = f"rucio replica remove {scope}:{name} --rse {mock_rse}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    # Check the dataset commands

    dids = did_factory.upload_test_dataset(rse_name=mock_rse, scope=scope, size=1, nb_files=1)
    dataset_name = dids[0]['dataset_name']

    cmd = f"rucio replica list dataset {scope}:{dataset_name} --deep"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dataset_name in out

    cmd = f"rucio replica list dataset --rse {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert all([dataset in out for dataset in rucio_client.list_datasets_per_rse(mock_rse)])


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


def test_rse(rucio_client):
    rse_name = rse_name_generator()

    cmd = f"rucio rse add {rse_name}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rse_name in [i['rse'] for i in rucio_client.list_rses(rse_name)]

    cmd = "rucio rse list"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rse_name in out

    cmd = f"rucio rse show {rse_name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rse_name in out

    value = rse_name_generator()
    cmd = f"rucio rse update {rse_name} --key city --value {value}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert value == rucio_client.list_rse_attributes(rse_name)['city']

    cmd = f"rucio rse remove {rse_name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rse_name not in [i for i in rucio_client.list_rses(rse_name)]


def test_rse_attribute():
    rse_name = rse_name_generator()
    _, _, err = execute(f"rucio rse add {rse_name}")
    assert "ERROR" not in err

    cmd = f"rucio rse attribute list {rse_name}"
    _, _, err = execute(cmd)
    assert "ERROR" not in err

    cmd = f"rucio rse attribute add {rse_name} --key name --value {rse_name}"
    _, _, err = execute(cmd)
    assert "ERROR" not in err


def test_rse_protocol():
    rse_name = rse_name_generator()
    _, _, err = execute(f"rucio rse add {rse_name}")
    assert "ERROR" not in err

    domain_json = """{"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0}}"""
    cmd = f"rucio rse protocol add {rse_name} --hostname blocklistreplica --scheme file --prefix /rucio --port 0 --impl rucio.rse.protocols.posix.Default --domain-json '{domain_json}'"
    exitcode, _, err = execute(cmd)
    print(err)
    assert "ERROR" not in err
    assert exitcode == 0

    cmd = f"rucio rse protocol remove {rse_name} --hostname blocklistreplica --scheme file"
    exitcode, _, err = execute(cmd)
    print(err)
    assert exitcode == 0
    assert "ERROR" not in err


def test_rse_distance():
    source_rse = "MOCK"
    dest_rse = "MOCK2"

    cmd = f"rucio rse distance remove {source_rse} {dest_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    if "ERROR" in err:
        assert f"Distance from {source_rse} to {dest_rse}" in err

    cmd = f"rucio rse distance add {source_rse} {dest_rse} --distance 1"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio rse distance show {source_rse} {dest_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dest_rse in out
    assert "1" in out

    cmd = f"rucio rse distance update {source_rse} {dest_rse} --distance 10"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio rse distance show {source_rse} {dest_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert dest_rse in out
    assert "10" in out

    cmd = f"rucio rse distance remove {source_rse} {dest_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err


def test_rse_limits(rucio_client):
    mock_rse = 'MOCK'
    limit = "mock_limit"

    cmd = f"rucio rse limit add {mock_rse} --limit {limit} 100"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert 100 == rucio_client.get_rse_limits(mock_rse)[limit]

    cmd = f"rucio rse limit remove {mock_rse} --limit {limit}"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    try:
        assert limit not in rucio_client.get_rse_limits(mock_rse).keys()
    except RucioException:  # Can throw an error if the mock_rse has no limits
        pass

    not_int_limit = "askjd"
    cmd = f"rucio rse limit add {mock_rse} --limit {limit}_2 {not_int_limit}"
    exitcode, _, err = execute(cmd)
    assert exitcode != 0
    assert f"'{not_int_limit}' is not a valid integer" in err  # The click error message for invalid type

    non_existent_limit = "askjd"
    cmd = f"rucio rse limit remove {mock_rse} --limit {non_existent_limit}"
    exitcode, _, err = execute(cmd)
    assert exitcode != 0
    assert f'Limit {non_existent_limit} not defined in RSE {mock_rse}' in err


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


@pytest.mark.dirty
@pytest.mark.flaky(reruns=3, reruns_delay=5)
def test_rule(rucio_client, mock_scope):
    mock_rse = "MOCK-POSIX"
    rule_rse = "MOCK"

    scope = mock_scope.external
    name = generate_uuid()
    rucio_client.add_replica(rse=mock_rse, scope=scope, name=name, bytes_=4, adler32="deadbeef")

    cmd = f"rucio rule add {scope}:{name} --copies 1 --rses {rule_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    rule_id = out.split("\n")[0]

    cmd = f"rucio rule list --did {scope}:{name}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rule_id in out

    cmd = f"rucio rule list --account {rucio_client.account}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert rule_id in out

    cmd = "rucio rule list"
    exitcode, out, err = execute(cmd)
    assert exitcode != 0
    assert "At least one option has to be given" in err

    move_rse = "MOCK2"
    cmd = f"rucio rule move {rule_id} --rses {move_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = f"rucio rule update {rule_id} --priority 3"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    # Check that you can lock and unlock a rule
    cmd = f"rucio rule update {rule_id} --locked False"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert not rucio_client.get_replication_rule(rule_id)['locked']

    cmd = f"rucio -v rule update {rule_id} --locked True"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert rucio_client.get_replication_rule(rule_id)['locked']

    # Testing the two different lifetime type options
    cmd = f"rucio rule update {rule_id} --lifetime 10"
    exitcode, out, err = execute(cmd)
    print(out, err)
    assert exitcode == 0
    assert "ERROR" not in err
    rule_info = rucio_client.get_replication_rule(rule_id)
    assert abs(rule_info["updated_at"] - rule_info["expires_at"]).seconds == 10

    cmd = f"rucio rule update {rule_id} --lifetime None"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rucio_client.get_replication_rule(rule_id)["expires_at"] is None

    cmd = f"rucio rule update {rule_id} --suspend"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert rucio_client.get_replication_rule(rule_id)["state"] == "SUSPENDED"

    # Do one without a child rule so i can delete it
    new_name = generate_uuid()
    rucio_client.add_replica(mock_rse, scope, new_name, 4, "deadbeef")
    cmd = f"rucio rule add {scope}:{new_name} --copies 1 --rses {mock_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    rule_id = out.strip("\n")

    cmd = f"rucio rule remove {rule_id}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    # Add a rule with a lifetime
    scope = mock_scope.external
    name = generate_uuid()
    rucio_client.add_replica(rse=mock_rse, scope=scope, name=name, bytes_=4, adler32="deadbeef")

    cmd = f"rucio rule add {scope}:{name} " \
        "--lifetime 2592000 " \
        f"--rses {rule_rse} " \
        "--copies 1"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    # Can make a rule for multiple DIDs at once
    name1 = generate_uuid()
    rucio_client.add_replica(rse=mock_rse, scope=scope, name=name1, bytes_=4, adler32="deadbeef")
    name2 = generate_uuid()
    rucio_client.add_replica(rse=mock_rse, scope=scope, name=name2, bytes_=4, adler32="deadbeef")

    cmd = f"rucio rule add {scope}:{name1} {scope}:{name2} --copies 1 --rses {rule_rse}"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    assert len(out.split("\n")) == 3  # Creates two rules with independent IDs and one extra line at the end


def test_scope():
    new_scope = scope_name_generator()
    cmd = f"rucio scope add {new_scope} --account root"
    exitcode, _, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err

    cmd = "rucio scope list --account root"
    exitcode, out, err = execute(cmd)
    assert exitcode == 0
    assert "ERROR" not in err
    # assert new_scope in out
    # See issue https://github.com/rucio/rucio/issues/7316


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
