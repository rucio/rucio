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

import re

import pytest

from rucio.common.constants import OPENDATA_DID_STATE_LITERAL
from rucio.common.exception import DataIdentifierNotFound, OpenDataDataIdentifierAlreadyExists, OpenDataDataIdentifierNotFound, OpenDataInvalidStateUpdate
from rucio.common.utils import execute
from rucio.core import opendata
from rucio.core.did import add_did, set_status
from rucio.db.sqla.constants import DIDType, OpenDataDIDState
from rucio.db.sqla.session import get_session
from rucio.db.sqla.util import json_implemented
from rucio.tests.common import auth, did_name_generator, headers

skip_unsupported_json = pytest.mark.skipif(
    not json_implemented(),
    reason="JSON support is not implemented in this database"
)

skip_unsupported_dialect = pytest.mark.skipif(
    get_session().bind.dialect.name in ['oracle', 'sqlite'],
    reason=f"Unsupported dialect: {get_session().bind.dialect.name}"
)


class TestOpenDataCommon:
    def test_opendata_did_states(self):
        """
        Test that the OpenDataDIDState enum contains all expected states which are defined as a Literal in common/constants.py
        """

        opendata_did_state_from_common = set([state.upper() for state in OPENDATA_DID_STATE_LITERAL.__args__])
        opendata_did_state_from_enum = set([state.name for state in OpenDataDIDState])

        assert opendata_did_state_from_common == opendata_did_state_from_enum, "'OpenDataDIDState' enum does not match expected states from 'OPENDATA_DID_STATE_LITERAL'"


class TestOpenDataCore:
    def test_opendata_dids_add(self, mock_scope, root_account, db_write_session):
        dids = [
            {"scope": mock_scope, "name": did_name_generator(did_type="dataset")} for _ in range(6)
        ]

        for did in dids[0:5]:
            add_did(scope=did["scope"], name=did["name"], account=root_account, did_type=DIDType.DATASET,
                    session=db_write_session)

        # Add to open data in bulk
        opendata.add_opendata_dids(dids=dids[0:4], session=db_write_session)

        # Add one by one
        opendata.add_opendata_did(scope=dids[4]["scope"], name=dids[4]["name"], session=db_write_session)

        db_write_session.commit()

        # Test defaults
        opendata_did = opendata.get_opendata_did(scope=dids[0]["scope"], name=dids[0]["name"], session=db_write_session)

        assert opendata_did["scope"] == dids[0]["scope"], "Scope does not match"
        assert opendata_did["name"] == dids[0]["name"], "Name does not match"
        assert opendata_did["state"] == OpenDataDIDState.DRAFT

        # Add one not added yet as a DID
        with pytest.raises(DataIdentifierNotFound):
            opendata.add_opendata_did(scope=dids[5]["scope"], name=dids[5]["name"], session=db_write_session)

        db_write_session.commit()

        # Add one already added
        with pytest.raises(OpenDataDataIdentifierAlreadyExists):
            opendata.add_opendata_did(scope=dids[0]["scope"], name=dids[0]["name"], session=db_write_session)

    def test_opendata_dids_defaults(self, mock_scope, root_account, db_write_session):
        name = did_name_generator(did_type="dataset")

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET, session=db_write_session)

        opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        db_write_session.commit()

        opendata_did = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        default_keys = ["scope", "name", "state", "created_at", "updated_at"]
        for key in default_keys:
            assert key in opendata_did, f"Key {key} not found in opendata_did"

        assert opendata_did["scope"] == mock_scope, "Scope does not match"
        assert opendata_did["name"] == name, "Name does not match"
        assert opendata_did["state"] == OpenDataDIDState.DRAFT, "State does not match"

    def test_opendata_dids_remove(self, mock_scope, root_account, db_write_session):
        name = did_name_generator(did_type="dataset")

        with pytest.raises(OpenDataDataIdentifierNotFound):
            opendata.delete_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET, session=db_write_session)

        with pytest.raises(OpenDataDataIdentifierNotFound):
            opendata.delete_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        for _ in range(3):
            opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

            db_write_session.commit()

            opendata_did = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)

            assert opendata_did["scope"] == mock_scope, "Scope does not match"
            assert opendata_did["name"] == name, "Name does not match"

            opendata.delete_opendata_did(scope=mock_scope, name=name, session=db_write_session)

            with pytest.raises(OpenDataDataIdentifierNotFound):
                opendata.delete_opendata_did(scope=mock_scope, name=name, session=db_write_session)

            db_write_session.commit()

            with pytest.raises(OpenDataDataIdentifierNotFound):
                opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)

    def test_opendata_dids_update(self, mock_scope, root_account, db_write_session):
        name = did_name_generator(did_type="dataset")

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET, session=db_write_session)
        opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        db_write_session.commit()

        state = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["state"]

        assert state == OpenDataDIDState.DRAFT

        with pytest.raises(OpenDataInvalidStateUpdate):
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.SUSPENDED,
                                         session=db_write_session)

        with pytest.raises(OpenDataInvalidStateUpdate):
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                         session=db_write_session)

        set_status(scope=mock_scope, name=name, open=False, session=db_write_session)
        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                     session=db_write_session)

        db_write_session.commit()

        state = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["state"]

        assert state == OpenDataDIDState.PUBLIC

        with pytest.raises(OpenDataInvalidStateUpdate):
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.DRAFT,
                                         session=db_write_session)

        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.SUSPENDED,
                                     session=db_write_session)

        db_write_session.commit()

        state = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["state"]

        assert state == OpenDataDIDState.SUSPENDED

        with pytest.raises(OpenDataInvalidStateUpdate):
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.DRAFT,
                                         session=db_write_session)

        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                     session=db_write_session)

        db_write_session.commit()

        state = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["state"]

        assert state == OpenDataDIDState.PUBLIC

    @skip_unsupported_dialect
    def test_opendata_dids_meta_update(self, mock_scope, root_account, db_write_session):
        name = did_name_generator(did_type="dataset")

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET,
                session=db_write_session)
        opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        db_write_session.commit()

        meta = opendata.get_opendata_meta(scope=mock_scope, name=name, session=db_write_session)

        assert meta == {}, "'meta' should be empty"
        meta_new = {"test": "test", "key": {"test": "test"}}

        opendata.update_opendata_did(scope=mock_scope, name=name, meta=meta_new, session=db_write_session)

        db_write_session.commit()

        meta = opendata.get_opendata_meta(scope=mock_scope, name=name, session=db_write_session)

        assert meta == meta_new, "'meta' should be updated"

    def test_opendata_doi_update(self, mock_scope, root_account, doi_factory, db_write_session):
        name = did_name_generator(did_type="dataset")

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET,
                session=db_write_session)
        opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        doi = doi_factory()

        opendata.update_opendata_did(scope=mock_scope, name=name, doi=doi, session=db_write_session)

        db_write_session.commit()

        doi_after = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["doi"]

        assert doi_after == doi, "DOI should be updated"

        db_write_session.commit()

        doi_after = opendata.get_opendata_doi(scope=mock_scope, name=name, session=db_write_session)

        assert doi_after == doi, "DOI should be updated"

        doi = doi_factory()
        opendata.update_opendata_doi(scope=mock_scope, name=name, doi=doi, session=db_write_session)

        db_write_session.commit()

        doi_after = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["doi"]

        assert doi_after == doi, "DOI should be updated"

    def test_opendata_dids_list(self, mock_scope, root_account, db_write_session):
        dids = [
            {"scope": mock_scope, "name": did_name_generator(did_type="dataset")} for _ in range(5)
        ]

        for did in dids:
            add_did(scope=did["scope"], name=did["name"], account=root_account, did_type=DIDType.DATASET,
                    session=db_write_session)
            opendata.add_opendata_did(scope=did["scope"], name=did["name"], session=db_write_session)

        opendata_dids = opendata.list_opendata_dids(session=db_write_session)["dids"]

        for did in dids:
            index = next(i for i, d in enumerate(opendata_dids) if d["name"] == did["name"])
            assert opendata_dids[index]["scope"] == did["scope"], "Scope does not match"
            assert opendata_dids[index]["name"] == did["name"], "Name does not match"
            assert opendata_dids[index]["state"] == OpenDataDIDState.DRAFT, "State does not match"

    def test_opendata_dids_list_public(self, mock_scope, root_account, db_write_session):
        did_private_name = did_name_generator(did_type="dataset")
        did_public_name = did_name_generator(did_type="dataset")

        opendata_public_number_before = len(
            opendata.list_opendata_dids(state=OpenDataDIDState.PUBLIC, session=db_write_session)["dids"])

        add_did(scope=mock_scope, name=did_private_name, account=root_account, did_type=DIDType.DATASET,
                session=db_write_session)
        add_did(scope=mock_scope, name=did_public_name, account=root_account, did_type=DIDType.DATASET,
                session=db_write_session)

        opendata.add_opendata_did(scope=mock_scope, name=did_private_name, session=db_write_session)
        opendata.add_opendata_did(scope=mock_scope, name=did_public_name, session=db_write_session)
        set_status(scope=mock_scope, name=did_public_name, open=False, session=db_write_session)
        opendata.update_opendata_did(scope=mock_scope, name=did_public_name, state=OpenDataDIDState.PUBLIC,
                                     session=db_write_session)

        opendata_public_number_after = len(
            opendata.list_opendata_dids(state=OpenDataDIDState.PUBLIC, session=db_write_session)["dids"])

        assert opendata_public_number_after - opendata_public_number_before == 1, "Public number should be 1 more"

        db_write_session.commit()

        opendata_did_public_new = opendata.get_opendata_did(scope=mock_scope, name=did_public_name,
                                                            session=db_write_session)

        assert opendata_did_public_new["scope"] == mock_scope, "Scope does not match"
        assert opendata_did_public_new["name"] == did_public_name, "Name does not match"
        assert opendata_did_public_new["state"] == OpenDataDIDState.PUBLIC, "State does not match"


class TestOpenDataClient:
    def test_opendata_dids_list_client(self, mock_scope, rucio_client):
        scope = str(mock_scope)
        dids = [
            {"scope": scope, "name": did_name_generator(did_type="dataset")} for _ in range(5)
        ]
        dids.sort(key=lambda x: x["name"])

        for did in dids:
            rucio_client.add_did(scope=did["scope"], name=did["name"], did_type="DATASET")
            rucio_client.add_opendata_did(scope=did["scope"], name=did["name"])

        opendata_dids = rucio_client.list_opendata_dids()["dids"]

        for did in dids:
            did_output = next((d for d in opendata_dids if d["name"] == did["name"]), None)
            assert did_output is not None, f"Did {did['name']} not found in opendata_dids"
            assert did_output["scope"] == str(did["scope"]), "Scope does not match"
            assert did_output["name"] == did["name"], "Name does not match"
            assert did_output["state"] == "DRAFT", "State does not match"

    def test_opendata_dids_public_list_client(self, mock_scope, rucio_client):
        scope = str(mock_scope)
        dids = [
            {"scope": scope, "name": did_name_generator(did_type="dataset")} for _ in range(5)
        ]
        dids.sort(key=lambda x: x["name"])

        opendata_dids_before = rucio_client.list_opendata_dids()["dids"]

        for did in dids:
            rucio_client.add_did(scope=did["scope"], name=did["name"], did_type="DATASET")
            rucio_client.add_opendata_did(scope=did["scope"], name=did["name"])

        # set number 2 and 3 to public
        rucio_client.set_status(scope=dids[1]["scope"], name=dids[1]["name"], open=False)
        rucio_client.update_opendata_did(scope=dids[1]["scope"], name=dids[1]["name"], state="public")

        rucio_client.set_status(scope=dids[2]["scope"], name=dids[2]["name"], open=False)
        rucio_client.update_opendata_did(scope=dids[2]["scope"], name=dids[2]["name"], state="public")

        # set number 4 to public
        rucio_client.set_status(scope=dids[3]["scope"], name=dids[3]["name"], open=False)
        rucio_client.update_opendata_did(scope=dids[3]["scope"], name=dids[3]["name"], state="public")
        # then suspend it
        rucio_client.update_opendata_did(scope=dids[3]["scope"], name=dids[3]["name"], state="suspended")

        opendata_dids = rucio_client.list_opendata_dids(public=True)["dids"]
        opendata_dids = [d for d in opendata_dids if d not in opendata_dids_before]
        opendata_dids.sort(key=lambda x: x["name"])

        # only 2 and 3 should be present in response
        assert len(opendata_dids) == 2, "There should be only 2 more public DIDs"
        for did_input, did_output in zip(dids[1:3], opendata_dids):
            assert did_output["scope"] == str(did_input["scope"]), "Scope does not match"
            assert did_output["name"] == did_input["name"], "Name does not match"
            assert did_output["state"] == "PUBLIC", "State does not match"

    def test_opendata_show_client(self, mock_scope, rucio_client):
        name = did_name_generator(did_type="dataset")
        scope = str(mock_scope)

        # Add it as a DID
        rucio_client.add_did(scope=scope, name=name, did_type="DATASET")

        # Add it as open data
        rucio_client.add_opendata_did(scope=scope, name=name)
        opendata_did = rucio_client.get_opendata_did(scope=scope, name=name)

        assert opendata_did["scope"] == scope, "Scope does not match"
        assert opendata_did["name"] == name, "Name does not match"
        assert opendata_did["state"] == "DRAFT", "State does not match"

        # Here we also test that doi is returned as key by default because `include_doi` is True by default
        assert opendata_did["doi"] is None, "DOI should be None"
        assert "files" not in opendata_did, "Files should not be present in the response"
        assert "meta" not in opendata_did, "Meta should not be present in the response"

        opendata_did = rucio_client.get_opendata_did(scope=scope, name=name,
                                                     include_files=True, include_metadata=True, include_doi=True)
        assert opendata_did["doi"] is None, "DOI should still be None"
        assert "files" in opendata_did, "Files should be present in the response"
        assert "meta" in opendata_did, "Meta should be present in the response"
        meta = opendata_did["meta"]
        assert meta == {}, "'meta' should be empty"


class TestOpenDataAPI:
    api_endpoint = '/opendata/dids'
    api_endpoint_public = '/opendata/public/dids'

    def test_opendata_api_list(self, rest_client, auth_token, root_account):
        response = rest_client.get(
            self.api_endpoint,
            headers=headers(auth(auth_token)),
        )
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"

    def test_opendata_public_api_list(self, rest_client):
        response = rest_client.get(
            self.api_endpoint_public,
        )
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"

    def test_opendata_api_add_remove(self, rest_client, auth_token, root_account, mock_scope):
        name = did_name_generator(did_type="dataset")
        endpoint = f"{self.api_endpoint}/{mock_scope}/{name}"
        request_headers = headers(auth(auth_token))

        # Try to add it, should fail because DID does not exist
        response = rest_client.post(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 404, f"Expected 404 Not Found, got {response.status_code}"

        # Try to remove, should fail because it does not exist
        response = rest_client.delete(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 404, f"Expected 404 Not Found, got {response.status_code}"

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)

        # Try to register as Opendata again, now it should succeed
        response = rest_client.post(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 201, f"Expected 200 OK, got {response.status_code}"

        # Add it again, should fail because it already exists
        response = rest_client.post(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 409, f"Expected 409 Conflict, got {response.status_code}"

        # Delete it
        response = rest_client.delete(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 204, f"Expected 204 OK, got {response.status_code}"

        # Delete it again, should fail because it does not exist
        response = rest_client.delete(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 404, f"Expected 404 Not Found, got {response.status_code}"


class TestOpenDataCLI:
    @staticmethod
    def extract_subcommands(stdout: str):
        match = re.search(r"(?i)^Commands:\n((?:\s{2,}\w+.*\n)+)", stdout, re.MULTILINE)
        assert match, "Failed to locate subcommands section in help output"

        lines = match.group(1).splitlines()
        # Extract the first word (command) from each line
        commands = {line.strip().split()[0] for line in lines if line.strip()}
        return commands

    @staticmethod
    def extract_options(stdout: str):
        match = re.search(r"(?i)^Options:\n((?:\s{2,}.+\n)+)", stdout, re.MULTILINE)
        assert match, "Failed to locate options section in help output"

        options_block = match.group(1)
        options = set()

        for line in options_block.splitlines():
            # Match all long-form options starting with "--"
            options.update(re.findall(r"--\w[\w-]*", line))

        return options

    def test_opendata_cli_invalid(self):
        cmd = "rucio opendata command-does-not-exist"
        exitcode, _, stderr = execute(cmd)
        assert exitcode != 0, f"Command '{cmd}' should have failed but succeeded"
        assert "ERROR" in stderr.upper()

    def test_opendata_cli_help(self):
        cmd = "rucio opendata did --help"
        exitcode, stdout, stderr = execute(cmd)
        assert exitcode == 0, f"Command '{cmd}' failed with error: {stderr.strip()}"
        assert "ERROR" not in stderr.upper(), f"Command '{cmd}' failed with error: {stderr.strip()}"

        subcommands_expected = {"add", "list", "show", "update", "remove"}
        subcommands = self.extract_subcommands(stdout)
        assert subcommands == subcommands_expected, f"Expected subcommands {subcommands_expected}, got {subcommands}"

    @pytest.mark.parametrize("subcommand, expected_options", [
        ("add", {"--help"}),
        ("list", {"--help", "--state", "--public"}),
        ("show", {"--help", "--meta", "--files", "--public"}),
        ("update", {"--help", "--meta", "--state", "--doi"}),
        ("remove", {"--help"}),
    ])
    def test_opendata_cli_options(self, subcommand, expected_options):
        exitcode, stdout, stderr = execute(f"rucio opendata did {subcommand} --help")
        assert exitcode == 0
        assert "ERROR" not in stderr.upper(), f"Command 'rucio opendata {subcommand} --help' failed with error: {stderr.strip()}"

        options = self.extract_options(stdout)
        assert options == expected_options, (
            f"Subcommand '{subcommand}': expected options {expected_options}, got {options}"
        )

    def test_opendata_cli_list_add_remove(self, mock_scope):
        exitcode, stdout, stderr = execute("rucio opendata did list")
        assert exitcode == 0, f"Command 'rucio opendata list' failed with error: {stderr.strip()}"
        assert "ERROR" not in stderr.upper(), f"Command 'rucio opendata list' failed with error: {stderr.strip()}"

        name = did_name_generator(did_type="dataset")

        exitcode, stdout, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 1, f"Expected failure when adding bad DID: {stderr.strip()}"
        assert "DataIdentifierNotFound" in stderr, "Expected 'DataIdentifierNotFound' error in output"

        exitcode, stdout, stderr = execute(f"rucio opendata did remove {mock_scope}:{name}")
        assert exitcode == 1, f"Expected failure when removing unregistered DID: {stderr.strip()}"
        assert "OpenDataDataIdentifierNotFound" in stderr, "Expected 'OpenDataDataIdentifierNotFound' error in output"

        exitcode, _, stderr = execute(f"rucio did add --type dataset {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to add dataset: {stderr.strip()}"

        exitcode, _, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to add opendata DID: {stderr.strip()}"

        exitcode, stdout, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 1, f"Expected failure when adding existing opendata DID: {stderr.strip()}"
        assert "OpenDataDataIdentifierAlreadyExists" in stderr, "Expected 'OpenDataDataIdentifierAlreadyExists' error in output"

        exitcode, stdout, stderr = execute("rucio opendata did list")
        assert exitcode == 0, f"Failed to list opendata: {stderr.strip()}"
        assert f"{name}" in stdout, f"Expected {mock_scope}:{name} in opendata list"

        exitcode, stdout, stderr = execute("rucio opendata did list --state draft")
        assert exitcode == 0, f"Failed to list opendata with state draft: {stderr.strip()}"
        assert f"{name}" in stdout, f"Expected {mock_scope}:{name} in opendata list with state draft"

        exitcode, stdout, stderr = execute("rucio opendata did list --state public")
        assert exitcode == 0, f"Failed to list opendata with state public: {stderr.strip()}"
        assert f"{name}" not in stdout, f"Expected {mock_scope}:{name} not in opendata list with state public"

        exitcode, stdout, stderr = execute("rucio opendata did list --state suspended")
        assert exitcode == 0, f"Failed to list opendata with state suspended: {stderr.strip()}"
        assert f"{name}" not in stdout, f"Expected {mock_scope}:{name} not in opendata list with state suspended"

        exitcode, _, stderr = execute(f"rucio opendata did remove {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to remove opendata DID: {stderr.strip()}"

        exitcode, stdout, stderr = execute("rucio opendata did list")
        assert exitcode == 0, f"Failed to list opendata after removal: {stderr.strip()}"
        assert f"{name}" not in stdout, f"Expected {mock_scope}:{name} not in opendata list after removal"

        exitcode, _, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to re-add opendata DID: {stderr.strip()}"

        exitcode, stdout, stderr = execute("rucio opendata did list --state draft")
        assert exitcode == 0, f"Failed to list opendata with state draft after re-adding: {stderr.strip()}"
        assert f"{name}" in stdout, f"Expected {mock_scope}:{name} in opendata list with state draft after adding again"

        exitcode, _, stderr = execute("rucio opendata did list --state invalid_state")
        assert exitcode != 0, "Expected non-zero exit code for invalid state"
        assert "ERROR" in stderr.upper(), "Expected error message for invalid state"
        valid_states = {"draft", "public", "suspended"}
        assert all(state in stderr for state in valid_states), (
            f"Expected valid states {valid_states} in error message, got {stderr}"
        )
