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

import datetime
import json
import tempfile

import pytest

from rucio import version
from rucio.common.exception import AccountNotFound
from rucio.common.utils import generate_uuid
from rucio.tests.common import account_name_generator, execute, rse_name_generator, scope_name_generator

rcom = "bin/rcom"


def test_ping():
    command = f"{rcom} --format json ping"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert json.loads(out.strip("\n")) == {"version": version.version_string()}


def test_ping_noauth():
    command = f"{rcom} --verbose --config errorconfig.cfg ping"
    exitcode, _, _ = execute(command)
    assert exitcode == 1


def test_whoami(rucio_client):
    command = f"{rcom} --format json whoami"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    # Only checking the keys, the timestamps change annoyingly
    assert json.loads(out.strip("\n")).keys() == rucio_client.whoami().keys()


def test_csv_format():
    command = f"{rcom} --format csv ping"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert out == f"version\r\n{version.version_string()}\r\n\n"  # the execute adds an annoying extra \n


def test_text_format():
    command = f"{rcom} --format text ping"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    expected_string = f"+-----------+\n| version   |\n|-----------|\n| {version.version_string()}    |\n+-----------+\n"
    assert out == expected_string


@pytest.mark.xfail(reason="Not Implemented")
def test_text_rich():
    command = f"{rcom} --format rich ping"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert out is not None


def test_account_methods():
    # Make a new account
    account_name = account_name_generator()
    command = f"{rcom} --format json add account --account-name {account_name} --type 'USER'"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # verify it shows up
    command = f"{rcom} --format json list account"
    exitcode, out, _ = execute(command)
    out = json.loads(out.strip("\n"))
    assert exitcode == 0
    for entry in out:
        if entry["account"] == account_name:
            out = entry
            break
    assert out["account"] == account_name
    assert out["type"] == "USER"

    # change the email
    new_email = f"{account_name}@default_location.edu"
    command = f"{rcom} set account --account-name {account_name} --account-key email --account-value {new_email}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # verify the change
    command = f"{rcom} --format json list account --account-name {account_name}"
    exitcode, out, _ = execute(command)
    out = json.loads(out.strip("\n"))
    assert exitcode == 0
    for entry in out:
        if entry["account"] == account_name:
            out = entry
            break
    assert out["email"] == new_email

    # delete the account
    command = f"{rcom} remove account --account-name {account_name}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    # make sure it stuck
    command = f"{rcom} --format json list account"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    out = json.loads(out.strip("\n"))
    names = [row["account"] for row in out]
    assert account_name not in names


def test_account_attribute(rucio_client):
    account_name = account_name_generator()
    rucio_client.add_account(account_name, type_="USER", email="anon@email.com")

    # add an attribute
    command = f"{rcom} add account attribute --account-name {account_name} --attr-key 'admin' --attr-value false"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    # verify
    command = f"{rcom} --format json list account attribute --account-name {account_name}"
    exitcode, out, _ = execute(command)
    out = json.loads(out.strip("\n"))

    assert exitcode == 0
    assert out[0]["key"] == "admin"
    assert not out[0]["value"]  # value: False

    # remove it
    command = f"{rcom} remove account attribute --account-name {account_name} --attr-key 'admin'"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} --format json list account attribute --account-name {account_name}"
    exitcode, out, err = execute(command)
    print(out, err)
    assert exitcode == 0
    out = json.loads(out.strip("\n"))
    assert len(out) == 0


def test_account_ban(rucio_client):
    account_name = account_name_generator()
    rucio_client.add_account(account_name, type_="USER", email="anon@email.com")

    command = f"{rcom} set account ban --account-name {account_name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    with pytest.raises(AccountNotFound):
        rucio_client.list_account_attributes(account=account_name)

    command = f"{rcom} unset account ban --account-name {account_name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    active = [account["account"] for account in rucio_client.list_accounts()]
    assert account_name in active


def test_account_identities(rucio_client):
    # do it correctly
    account_name = account_name_generator()
    email = "anon@email.com"
    rucio_client.add_account(account_name, type_="USER", email=email)
    command = f"{rcom} -v add account identities --account-name {account_name} --email {email} --auth-type GSS --identity '{email}'"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Check the list
    command = f"{rcom} --format json list account identities --account-name {account_name}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert email in [id["email"] for id in json.loads(out.strip("\n"))]

    # do it wrong
    command = f"{rcom} add account identities --account-name {account_name} --auth-type USERPASS --identity CN=Joe Doe"
    exitcode, _, _ = execute(command)
    assert exitcode != 0

    # remove an existing id
    command = f"{rcom} remove account identities --account-name {account_name} --auth-type GSS --identity '{email}'"
    exitcode, _, _ = execute(command)
    assert exitcode == 0


def test_account_limits(rse_factory, jdoe_account):
    rse, _ = rse_factory.make_posix_rse()
    account_name = jdoe_account.external

    local_limit = 10
    command = f"{rcom} add account limits --account-name {account_name} --rse {rse} --bytes {local_limit} --locality local"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} --format json list account limits --account-name {account_name} --rse {rse} --locality local"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert local_limit in [limit["bytes"] for limit in json.loads(out.strip("\n"))]

    command = f"{rcom} remove account limits --account-name {account_name} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} --format json list account limits --account-name {account_name} --rse {rse} --locality local"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert local_limit not in [limit["bytes"] for limit in json.loads(out.strip("\n"))]


def test_config():
    command = f"{rcom} set config --section mock_section --option mock_option --value mock_value"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Get the whole config
    command = f"{rcom} --format json list config"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    for result in json.loads(out.strip("\n")):
        assert {"section", "option", "value"} == set(result.keys())

    # Get just the added stuff
    command = f"{rcom} --format json list config --section mock_section"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    json_out = json.loads(out.strip("\n"))
    assert len(json_out) == 1
    for key, value in json_out[0].items():
        assert value == f"mock_{key}"

    # remove existing option
    command = f"{rcom} unset config --section mock_section --option mock_option"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # verify the mock one we added is gone
    command = f"{rcom} --format json list config --section mock_section"
    exitcode, _, _ = execute(command)
    # Throws an error in this case
    assert exitcode != 0


def test_scope(rucio_client, root_account):
    # Add a scope
    new_scope = scope_name_generator()
    rucio_client.add_scope(account=root_account.external, scope=new_scope)

    # Ensure its there
    command = f"{rcom} --format json list scope --account {root_account.external}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert new_scope in [entry["scope"] for entry in json.loads(out.strip("\n"))]

    # Add the new scope with
    new_scope = scope_name_generator()
    command = f"{rcom} add scope --account {root_account.external} --scope {new_scope}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Check its there
    command = f"{rcom} list scope --account {root_account.external}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert new_scope in [entry["scope"] for entry in json.loads(out.strip("\n"))]


def test_subscription(rucio_client, root_account):
    # make a fake sub
    sub_name = account_name_generator()  # Don't have a sub name generator, and the rules are the same
    filter_ = {"scope": ["user.jdoe"], "datatype": ["txt"]}
    rules = [{"copies": 1, "rse_expression": "JDOE_DATADISK", "lifetime": 3600, "activity": "User Subscriptions"}]
    sub_id = rucio_client.add_subscription(name=sub_name, account=root_account.external, filter_=filter_, replication_rules=rules, lifetime=1, retroactive=False, dry_run=False, comments="", priority=1)

    # Make sure list works
    command = f"{rcom} --format json list subscription"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert sub_id in [entry["id"] for entry in json.loads(out.strip("\n"))]
    assert sub_name in [entry["name"] for entry in json.loads(out.strip("\n"))]

    # Update it
    new_filter = json.dumps({"scope": ["user.jdoe"], "datatype": ["fake"]})
    command = f"{rcom} -v set subscription --name {sub_name} --filter '{new_filter}'"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    # List again
    command = f"{rcom} --format json list subscription"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    entry = [entry for entry in json.loads(out.strip("\n")) if entry["id"] == sub_id][0]
    assert entry["filter"] == new_filter

    # Add ones and then ensure its in the list
    sub_name = account_name_generator()

    command = f"{rcom} -v add subscription --name {sub_name} --filter '{json.dumps(filter_)}' --replication-rules '{json.dumps(rules)}' --comments comment"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} --format json list subscription"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert sub_name in [entry["name"] for entry in json.loads(out.strip("\n"))]


def test_did(rucio_client, rse_factory, did_factory, mock_scope):
    num_files = 2
    scope = mock_scope.external
    # make a dataset with 2 files in it and put those in a container
    dataset1 = did_factory.make_dataset()
    rse, _ = rse_factory.make_posix_rse()
    files = [did_factory.upload_test_file(rse) for _ in range(num_files)]
    rucio_client.attach_dids_to_dids([{"scope": scope, "name": dataset1["name"], "dids": [{"scope": scope, "name": file["name"]} for file in files]}])

    command = f"{rcom} --format json list did  --did {scope}:{dataset1['name']}"
    exitcode, out, _ = execute(command)
    included_outfiles = [entry["name"] for entry in json.loads(out.strip('\n'))]
    assert exitcode == 0
    for file in files:
        assert file["name"] in included_outfiles

    # List with stat
    command = f"{rcom} --format json list did  --stat --did {scope}:{dataset1['name']}"
    exitcode, out, _ = execute(command)
    included_outfiles = [entry for entry in json.loads(out.strip("\n"))]
    expected_keys = set(rucio_client.get_did(scope, dataset1['name'])[0].keys())

    assert exitcode == 0
    for file in files:
        assert file["name"] in [file['name'] for file in included_outfiles]
        assert set(file.keys()) == expected_keys

    # Add a new container
    new_container_name = scope_name_generator()  # There's not a did name generator, just a did generator
    command = f"{rcom} add did  --did {scope}:{new_container_name} --type container"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    returned_files = rucio_client.get_did(scope="mock", name=new_container_name)
    assert new_container_name == returned_files["name"]
    assert returned_files["type"] == "CONTAINER"

    # Add a new dataset
    new_container_name = scope_name_generator()  # There's not a did name generator, just a did generator
    command = f"{rcom} add did  --did {scope}:{new_container_name} --type dataset"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    returned_files = rucio_client.get_did(scope="mock", name=new_container_name)
    assert returned_files["type"] == "DATASET"

    # Remove an existing did
    command = f"{rcom} remove did  --did {scope}:{new_container_name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    returned_files = rucio_client.get_did(scope="mock", name=new_container_name)
    assert returned_files["expired_at"] is not None

    # Remove a non-existent one
    new_did_name = scope_name_generator()  # There's not a did name generator, just a did generator
    command = f"{rcom} remove did  --did {scope}:{new_did_name}"
    exitcode, _, err = execute(command)
    # This does work - but puts a warning in the log
    assert exitcode == 0
    assert "Failed to erase DID:" in err


def test_did_history(did_factory):
    dataset1 = did_factory.make_dataset()
    # TODO I have no idea what this is actually supposed to look like
    command = f"{rcom}  --format json list did history --did {dataset1['scope']}:{dataset1['name']}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0


def test_did_metadata(rucio_client, did_factory, rse_factory, mock_scope):
    plugin = "DID_COLUMN"

    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)

    meta_from_client = [rucio_client.get_metadata(scope=mock_scope.external, name=did["name"], plugin=plugin)]
    command = f"{rcom}  --format json list did metadata --did {did['scope']}:{did['name']} --plugin {plugin}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    readout = json.loads(out.strip("\n"))

    # Verify it's the same when I look at it from the client
    for target_did, read_did in zip(meta_from_client, readout):
        assert set(target_did.keys()) == set(read_did.keys())
        for key in target_did.keys():
            # convert to dates
            if hasattr(target_did[key], "month"):  # Check it's a datetime
                target_did[key] = f"{target_did[key]}"
            assert target_did[key] == read_did[key]

    key = "version"
    key_change = "a_sharp"

    # Now do some changes:
    command = f"{rcom} set did metadata --did {did['scope']}:{did['name']} --key {key} --value {key_change}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    readout = rucio_client.get_metadata(scope=mock_scope.external, name=did["name"], plugin=plugin)
    assert readout[key] == key_change

    # TODO Find a key I'm allowed to remove
    # command =  f"{rcom} unset did metadata --did {did['scope']}:{did['name']} --key {key}"
    # exitcode, out, err = execute(command)
    # print(out, err)
    # assert exitcode == 0
    # readout = rucio_client.get_metadata(scope=mock_scope.external, name=did['name'], plugin=plugin)
    # assert key  not in readout.keys()


def test_did_attachment(rucio_client, did_factory, rse_factory, mock_scope):
    rse, _ = rse_factory.make_posix_rse()
    child_did = did_factory.upload_test_file(rse)
    parent_did = did_factory.make_dataset()
    # Make a new dataset and file
    # Attach them
    rucio_client.attach_dids(scope=mock_scope.external, name=parent_did["name"], dids=[child_did])

    # Verify it went through
    # For the child:
    command = f"{rcom}  --format json list did attachment --parent --did {child_did['scope']}:{child_did['name']}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    readout = json.loads(out.strip("\n"))[0]  # should only be one
    assert readout["name"] == parent_did["name"]

    # For the parent:
    command = f"{rcom}  --format json list did attachment --child --did {parent_did['scope']}:{parent_did['name']}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    readout = json.loads(out.strip("\n"))[0]
    assert readout["name"] == child_did["name"]

    # Unattach
    command = f"{rcom} remove did attachment --did {child_did['scope']}:{child_did['name']} --target {parent_did['scope']}:{parent_did['name']}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    # Check the connection is gone-zo
    readout = rucio_client.list_parent_dids(scope=child_did["scope"].external, name=child_did["name"])
    assert len([i for i in readout]) == 0

    # Attach them again
    command = f"{rcom} add did attachment --did {child_did['scope']}:{child_did['name']} --target {parent_did['scope']}:{parent_did['name']}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    readout = rucio_client.list_parent_dids(scope=child_did["scope"].external, name=child_did["name"])
    readout = [i for i in readout]
    assert len(readout) == 1
    assert readout[0]["name"] == parent_did["name"]


def test_rse(rucio_client, rse_factory):
    # Add a rse
    rse, _ = rse_factory.make_posix_rse()
    command = f"{rcom} --format json list rse --rse {rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert rse in [r["rse"] for r in json.loads(out.strip("\n"))]

    command = f"{rcom} --format json list rse --rse {rse} --info"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert rse in [r["rse"] for r in json.loads(out.strip("\n"))]

    command = f"{rcom} remove rse --rse {rse} "
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    rses = rucio_client.list_rses()

    assert rse not in [r["rse"] for r in rses]

    rse_name = scope_name_generator().upper()
    command = f"{rcom} -v add rse --rse {rse_name} "
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    rses = rucio_client.list_rses(rse_expression=rse_name)

    assert rse_name in [r["rse"] for r in rses]


def test_rse_usage(rucio_client, rse_factory):
    rse, _ = rse_factory.make_posix_rse()

    command = f"{rcom} --format json list rse usage --rse {rse}"
    exitcode, out, _ = execute(command)
    out = json.loads(out.strip("\n"))
    assert exitcode == 0
    assert rse in [r["rse"] for r in out]

    true_usage = [i for i in rucio_client.get_rse_usage(rse)]
    for key, item in out[0].items():
        # I don't feel like doing the datetime conversion
        if key != "updated_at":
            assert true_usage[0][key] == item


def test_rse_distance(rucio_client, rse_factory):
    # list, add, remove, set
    rse_source, _ = rse_factory.make_posix_rse()
    rse_target, _ = rse_factory.make_posix_rse()

    distance = 5
    command = f"{rcom} add rse distance --rse {rse_source} --destination {rse_target} --distance {distance}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    read_distance = rucio_client.get_distance(rse_source, rse_target)[0]["distance"]
    assert read_distance == distance

    command = f"{rcom} list rse distance --rse {rse_source} --destination {rse_target}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert distance == json.loads(out.strip("\n"))["distance"]

    new_distance = 15
    command = f"{rcom} set rse distance --rse {rse_source} --destination {rse_target} --distance {new_distance}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    read_distance = rucio_client.get_distance(rse_source, rse_target)[0]["distance"]
    assert read_distance == new_distance

    command = f"{rcom} remove rse distance --rse {rse_source} --destination {rse_target} --distance {new_distance}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert len(rucio_client.get_distance(rse_source, rse_target)) == 0


def test_rse_attribute(rse_factory, rucio_client):
    rse, _ = rse_factory.make_mock_rse()
    key = "fake_attribute"
    value = "fake"

    command = f"{rcom} add rse attribute --rse {rse} --key {key} --value {value}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    readout = rucio_client.list_rse_attributes(rse)
    assert key in readout.keys()

    command = f"{rcom} remove rse attribute --rse {rse} --key {key}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    readout = rucio_client.list_rse_attributes(rse)
    assert key not in readout.keys()


def test_rse_protocol(rucio_client):
    # TODO I don't know how this is actually supposed to be tested, there are no existing tests for this in the bin

    rse = rse_name_generator()
    rucio_client.add_rse(rse)
    domain_json = '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}}'
    impl = 'rucio.rse.protocols.posix.Default'
    command = f"{rcom} -v add rse protocol --host-name jdoesprotocoltest --scheme file --prefix /rucio --port 0 --impl {impl} --domain-json \'{domain_json}\' --rse {rse} "
    exitcode, _, err = execute(command)
    print(err)
    assert exitcode == 0
    protocols = rucio_client.get_protocols(rse)
    assert 'file' in [i["scheme"] for i in protocols]

    command = f"{rcom} add remove protocol --host-name jdoesprotocoltest --port 0 --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    protocols = rucio_client.get_protocols(rse)
    assert 'file' not in [i["scheme"] for i in protocols]


def test_rse_limit(rucio_client, rse_factory):
    rse, _ = rse_factory.make_posix_rse()
    # add or remove
    name = "mock"
    limit = 10
    command = f"{rcom} add rse limit --rse {rse} --name {name} --limit {limit}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    rse_limits = [i for i in rucio_client.get_rse_limits(rse)][0]
    assert rse_limits == name

    command = f"{rcom} remove rse limit --rse {rse} --name {name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    assert len(rucio_client.get_rse_limits(rse)) == 0


def test_rse_qos(rucio_client, rse_factory):
    rse, _ = rse_factory.make_posix_rse()
    qos = "qos_policy"
    command = f"{rcom} add rse qos-policy --rse {rse} --qos_policy {qos}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    read_polices = [i for i in rucio_client.list_qos_policies(rse)]
    assert qos in read_polices

    command = f"{rcom} list rse qos-policy --rse {rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert read_polices == json.loads(out.strip("\n"))

    command = f"{rcom} remove rse qos-policy --rse {rse} --qos_policy {qos}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0
    read_polices = [i for i in rucio_client.list_qos_policies(rse)]
    assert qos not in read_polices


def test_replica(rse_factory, mock_scope):
    # source_rse, _ = rse_factory.make_posix_rse()
    rse, _ = rse_factory.make_posix_rse()

    scope = mock_scope.external
    container = "container_%s" % generate_uuid()
    dataset = "dataset_%s" % generate_uuid()
    # Make a few different replicas

    command = f"{rcom} -v add replica --replica-type dataset --rse {rse} --dids {scope}:{dataset}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} add replica --replica-type container --dids {scope}:{container} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Ensure the pyclient output is matched by rcom
    command = f"{rcom} --format json list replica  --replica-type dataset --dids {scope}:{dataset} --rse {rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    # The dataset doesn't have anything in it
    assert len(json.loads(out.strip("\n"))) == 0

    # Cannot remove a replica because we're missing permissions
    command = f"{rcom} remove replica --dids {scope}:{container}, {scope}:{dataset} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 2

    # TODO test for dataset containing many replicas


def test_replica_state(rse_factory, did_factory):
    # make a replica
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)

    # Make it bad
    command = f"{rcom} set replica state --bad --dids {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} --format json list replica state --bad --dids {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    readout = [i for i in json.loads(out.strip("\n"))]
    assert did["name"] in [r["name"] for r in readout]

    # Make it suspicious
    command = f"{rcom} set replica state --suspicious --dids {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Quintin Quarentino
    command = f"{rcom} set replica state --quarantine --dids {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # temp
    command = f"{rcom} set replica state --temporary-unavailable --dids {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Turn it back to the light side
    command = f"{rcom} unset replica state --dids {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0


def test_replica_pfn(rse_factory, did_factory):
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)

    pfn = f"pfn_{generate_uuid()}"
    mock_pfn_link = f"/lskf/{pfn}:/kljsf/{pfn}"
    command = f"{rcom} set replica pfn --did {did['scope'].external}:{did['name']} --rse {rse} --link {mock_pfn_link}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    command = f"{rcom} --format json list replica pfn --did {did['scope'].external}:{did['name']} --rse {rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert len([i["pfn"] for i in json.loads(out.strip("\n"))]) == 1


def test_replica_tombstone(rucio_client, mock_scope, rse_factory):
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    name = generate_uuid()
    rucio_client.add_replica(rse, scope, name, 4, "aaaaaaaa")

    command = f"{rcom} add replica tombstone --rse {rse} --did {scope}:{name}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # TODO client command to view tombstones


@pytest.mark.xfail(reason="Client does not properly interact with model")
def test_lifetime_exception(rucio_client, mock_scope, did_factory, root_account):

    # Add an exception, verify it's included
    exception_dataset = did_factory.make_dataset()
    rucio_client.set_metadata(scope=mock_scope.external, name=exception_dataset["name"], key="eol_at", value="2028-01-01")
    rucio_client.set_config_option(section="lifetime_model", option="cutoff_date", value=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).strftime("%Y-%m-%d"))

    _ = rucio_client.add_exception(dids=[exception_dataset], pattern="", account=root_account, comments="Testing", expires_at="2130-01-01")

    command = f"{rcom} --format json list lifetime_exception"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    readout = json.loads(out.strip("\n"))
    assert exception_dataset["name"] in [i["name"] for i in readout]  # Make sure it's there

    temp_file = tempfile.NamedTemporaryFile()
    passing_did = did_factory.make_dataset()
    rucio_client.set_metadata(scope=mock_scope.external, name=passing_did["name"], key="eol_at", value="2028-01-01")

    files = [
        did_factory.make_dataset(),  # Default one does not have the eol_at field - this will fail
        did_factory.upload_file(),  # Can't add files
        did_factory.make_container(),  # Container that contains nothing - will not be included but won't resolve to anything
        passing_did,  # Only one that will be acted on
    ]

    with temp_file as f:
        for file_name in files:
            f.write(file_name)
        f.close()

    # Adding an exception through the client
    command = f"{rcom} --format json add lifetime_exception --input-file {temp_file.name} --reason Testing --expires_at 2130-01-01"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    summary = json.loads(out.strip("\n"))
    assert summary['"DID not submitted because it is a file"'] == 1
    assert summary["DID not submitted because it is not part of the lifetime campaign"] == 1
    assert summary["DID that are containers and were resolved"] == 0
    assert summary["DID successfully submitted including the one from containers resolved"] == 1


def test_rule(rucio_client, mock_scope, rse_factory, did_factory):
    # setup
    og_rse, _ = rse_factory.make_posix_rse()
    source_rse, _ = rse_factory.make_posix_rse()
    target_rse, _ = rse_factory.make_posix_rse()
    child_did = did_factory.upload_test_file(og_rse)

    # create rule
    command = f"{rcom} --format json add rule --dids {mock_scope.external}:{child_did['name']} --rse-expression {source_rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    created_rules = json.loads(out.strip("\n"))
    assert len(created_rules) != 0
    rule_id = created_rules["rule_id"][0]

    # List the rules with the py client
    listed_rules = rucio_client.list_did_rules(scope=mock_scope.external, name=child_did["name"])

    # Verify it matches list rule
    assert rule_id in [rule["id"] for rule in listed_rules]

    # Verify that matches the cli
    command = f"{rcom} --format json list rule --dids {mock_scope.external}:{child_did['name']} --rse-expression {source_rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
    assert rule_id in [rule["id"] for rule in json.loads(out.strip("\n"))]

    # Set rse = other rse
    command = f"{rcom} set rule --rule-id {rule_id} --move --rse-expression {target_rse}"
    exitcode, _, _ = execute(command)
    assert exitcode == 0

    # Will only be in both now
    listed_rules = rucio_client.list_did_rules(scope=mock_scope.external, name=child_did["name"])
    for rule in listed_rules:
        if rule["id"] == rule_id:
            assert rule["rse_expression"] in [target_rse, source_rse]

    # Make a new one and then remove it unmodified.
    new_rse, _ = rse_factory.make_posix_rse()
    command = f"{rcom} --format json add rule --dids {mock_scope.external}:{child_did['name']} --rse-expression {new_rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0

    created_rules = json.loads(out.strip("\n"))
    rule_id = created_rules["rule_id"][0]
    command = f"{rcom} remove rule --rule-id {rule_id} --rse-expression {new_rse}"
    exitcode, out, _ = execute(command)
    assert exitcode == 0
