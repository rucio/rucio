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

import pytest

from rucio.common.exception import OpenDataDataIdentifierAlreadyExists, OpenDataDataIdentifierNotFound, OpenDataInvalidStateUpdate
from rucio.core import opendata
from rucio.core.did import add_did, set_status
from rucio.db.sqla import session
from rucio.db.sqla.constants import DIDType, OpenDataDIDState
from rucio.db.sqla.util import json_implemented
from rucio.tests.common import did_name_generator, doi_generator

skip_unsupported_json = pytest.mark.skipif(
    not json_implemented(),
    reason="JSON support is not implemented in this database"
)

skip_unsupported_dialect = pytest.mark.skipif(
    session.get_session().bind.dialect.name in ['oracle', 'sqlite'],
    reason=f"Unsupported dialect: {session.get_session().bind.dialect.name}"
)


class TestOpenDataCore:
    def test_opendata_dids_add(self, mock_scope, root_account):
        dids = [
            {"scope": mock_scope, "name": did_name_generator(did_type="dataset")} for _ in range(6)
        ]

        for did in dids[0:5]:
            add_did(scope=did["scope"], name=did["name"], account=root_account, did_type=DIDType.DATASET)

        # Add to open data in bulk
        opendata.add_opendata_dids(dids=dids[0:4])

        # Add one by one
        opendata.add_opendata_did(scope=dids[4]["scope"], name=dids[4]["name"])

        # Add one not added yet as a did
        with pytest.raises(OpenDataDataIdentifierNotFound):
            opendata.add_opendata_did(scope=dids[5]["scope"], name=dids[5]["name"])

        # Add one already added
        with pytest.raises(OpenDataDataIdentifierAlreadyExists):
            opendata.add_opendata_did(scope=dids[0]["scope"], name=dids[0]["name"])

        # Test defaults
        opendata_did = opendata.get_opendata_did(scope=dids[0]["scope"], name=dids[0]["name"])
        assert opendata_did["scope"] == dids[0]["scope"], "Scope does not match"
        assert opendata_did["name"] == dids[0]["name"], "Name does not match"
        # The initial state should be DRAFT
        state = opendata_did["state"]
        assert state == OpenDataDIDState.DRAFT

    def test_opendata_dids_defaults(self, mock_scope, root_account):
        name = did_name_generator(did_type="dataset")

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)

        # Add it as open data
        opendata.add_opendata_did(scope=mock_scope, name=name)

        # Test defaults
        opendata_did = opendata.get_opendata_did(scope=mock_scope, name=name)
        default_keys = ["scope", "name", "state", "created_at", "updated_at"]
        for key in default_keys:
            assert key in opendata_did, f"Key {key} not found in opendata_did"

        assert opendata_did["scope"] == mock_scope, "Scope does not match"
        assert opendata_did["name"] == name, "Name does not match"
        assert opendata_did["state"] == OpenDataDIDState.DRAFT, "State does not match"

    def test_opendata_dids_remove(self, mock_scope, root_account):
        name = did_name_generator(did_type="dataset")

        # Try to delete it first, should fail because it does not exist
        with pytest.raises(OpenDataDataIdentifierNotFound):
            opendata.delete_opendata_did(scope=mock_scope, name=name)

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)

        # Should still fail because it's not added as open data
        with pytest.raises(OpenDataDataIdentifierNotFound):
            opendata.delete_opendata_did(scope=mock_scope, name=name)

        # Test it a few times just in case
        for _ in range(3):
            # Add it as open data
            opendata.add_opendata_did(scope=mock_scope, name=name)

            opendata_did = opendata.get_opendata_did(scope=mock_scope, name=name)
            assert opendata_did["scope"] == mock_scope, "Scope does not match"
            assert opendata_did["name"] == name, "Name does not match"

            opendata.delete_opendata_did(scope=mock_scope, name=name)

            with pytest.raises(OpenDataDataIdentifierNotFound):
                opendata.delete_opendata_did(scope=mock_scope, name=name)

            with pytest.raises(OpenDataDataIdentifierNotFound):
                opendata.get_opendata_did(scope=mock_scope, name=name)

    def test_opendata_dids_update(self, mock_scope, root_account):
        name = did_name_generator(did_type="dataset")

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)
        opendata.add_opendata_did(scope=mock_scope, name=name)

        state = opendata.get_opendata_did(scope=mock_scope, name=name)["state"]
        assert state == OpenDataDIDState.DRAFT

        with pytest.raises(OpenDataInvalidStateUpdate):
            # cannot go from draft to suspended
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.SUSPENDED)

        with pytest.raises(OpenDataInvalidStateUpdate):
            # DID needs to be closed before it can be made public
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC)

        # close DID
        set_status(scope=mock_scope, name=name, open=False)

        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC)
        state = opendata.get_opendata_did(scope=mock_scope, name=name)["state"]
        assert state == OpenDataDIDState.PUBLIC

        with pytest.raises(OpenDataInvalidStateUpdate):
            # cannot go back to draft
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.DRAFT)

        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.SUSPENDED)
        state = opendata.get_opendata_did(scope=mock_scope, name=name)["state"]
        assert state == OpenDataDIDState.SUSPENDED

        with pytest.raises(OpenDataInvalidStateUpdate):
            # cannot go back to draft
            opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.DRAFT)

        # back to public
        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC)
        state = opendata.get_opendata_did(scope=mock_scope, name=name)["state"]
        assert state == OpenDataDIDState.PUBLIC

    @skip_unsupported_dialect
    def test_opendata_dids_meta_update(self, mock_scope, root_account):
        name = did_name_generator(did_type="dataset")

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)
        opendata.add_opendata_did(scope=mock_scope, name=name)

        meta = opendata.get_opendata_meta(scope=mock_scope, name=name)
        assert meta == {}, "'meta' should be empty"
        meta_new = {"test": "test", "key": {"test": "test"}}
        opendata.update_opendata_did(scope=mock_scope, name=name, meta=meta_new)
        meta = opendata.get_opendata_meta(scope=mock_scope, name=name)
        assert meta == meta_new, "'meta' should be updated"

    def test_opendata_doi_update(self, mock_scope, root_account):
        name = did_name_generator(did_type="dataset")
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)
        opendata.add_opendata_did(scope=mock_scope, name=name)

        doi = doi_generator()
        # generic update method
        opendata.update_opendata_did(scope=mock_scope, name=name, doi=doi)
        doi_after = opendata.get_opendata_did(scope=mock_scope, name=name)["doi"]
        assert doi_after == doi, "DOI should be updated"

        # also via a dedicated method
        doi_after = opendata.get_opendata_doi(scope=mock_scope, name=name)
        assert doi_after == doi, "DOI should be updated"

        doi = doi_generator()
        opendata.update_opendata_doi(scope=mock_scope, name=name, doi=doi)
        doi_after = opendata.get_opendata_doi(scope=mock_scope, name=name)
        assert doi_after == doi, "DOI should be updated"

    def test_opendata_dids_list(self, mock_scope, root_account):
        dids = [
            {"scope": mock_scope, "name": did_name_generator(did_type="dataset")} for _ in range(5)
        ]

        for did in dids:
            add_did(scope=did["scope"], name=did["name"], account=root_account, did_type=DIDType.DATASET)
            opendata.add_opendata_did(scope=did["scope"], name=did["name"])

        opendata_dids = opendata.list_opendata_dids()["dids"]

        for did in dids:
            index = next(i for i, d in enumerate(opendata_dids) if d["name"] == did["name"])
            assert opendata_dids[index]["scope"] == did["scope"], "Scope does not match"
            assert opendata_dids[index]["name"] == did["name"], "Name does not match"
            assert opendata_dids[index]["state"] == OpenDataDIDState.DRAFT, "State does not match"

    def test_opendata_dids_list_public(self, mock_scope, root_account):
        did_private_name = did_name_generator(did_type="dataset")
        did_public_name = did_name_generator(did_type="dataset")

        opendata_public_number_before = len(opendata.list_opendata_dids(state=OpenDataDIDState.PUBLIC)["dids"])

        # Add it as a DID
        add_did(scope=mock_scope, name=did_private_name, account=root_account, did_type=DIDType.DATASET)
        add_did(scope=mock_scope, name=did_public_name, account=root_account, did_type=DIDType.DATASET)

        # Add it as open data
        opendata.add_opendata_did(scope=mock_scope, name=did_private_name)
        opendata.add_opendata_did(scope=mock_scope, name=did_public_name)

        # Update state to public
        set_status(scope=mock_scope, name=did_public_name, open=False)
        opendata.update_opendata_did(scope=mock_scope, name=did_public_name, state=OpenDataDIDState.PUBLIC)

        opendata_public_number_after = len(opendata.list_opendata_dids(state=OpenDataDIDState.PUBLIC)["dids"])

        # List open data DIDs
        assert opendata_public_number_after - opendata_public_number_before == 1, "Public number should be 1 more"

        # get by name
        opendata_did_public_new = opendata.get_opendata_did(scope=mock_scope, name=did_public_name)

        assert opendata_did_public_new["scope"] == mock_scope, "Scope does not match"
        assert opendata_did_public_new["name"] == did_public_name, "Name does not match"
        assert opendata_did_public_new["state"] == OpenDataDIDState.PUBLIC, "State does not match"


@pytest.mark.skip(reason="Client tests not working, likely due to API not enabled in the test environment")
class TestOpenDataClient:
    def test_opendata_dids_list_client(self, mock_scope, root_account, rucio_client):
        dids = [
            {"scope": mock_scope, "name": did_name_generator(did_type="dataset")} for _ in range(5)
        ]
        dids.sort(key=lambda x: x["name"])

        for did in dids:
            add_did(scope=did["scope"], name=did["name"], account=root_account, did_type=DIDType.DATASET)
            opendata.add_opendata_did(scope=did["scope"], name=did["name"])

        opendata_dids = rucio_client.list_opendata_dids()["dids"]
        opendata_dids.sort(key=lambda x: x["name"])

        for did_input, did_output in zip(dids, opendata_dids):
            assert did_output["scope"] == did_input["scope"], "Scope does not match"
            assert did_output["name"] == did_input["name"], "Name does not match"
            assert did_output["state"] == OpenDataDIDState.DRAFT, "State does not match"

    def test_opendata_dids_public_list_client(self, mock_scope, root_account, rucio_client):
        dids = [
            {"scope": mock_scope, "name": did_name_generator(did_type="dataset")} for _ in range(5)
        ]
        dids.sort(key=lambda x: x["name"])

        for did in dids:
            add_did(scope=did["scope"], name=did["name"], account=root_account, did_type=DIDType.DATASET)
            opendata.add_opendata_did(scope=did["scope"], name=did["name"])

        # set number 2 and 3 to public
        opendata.update_opendata_did(scope=dids[1]["scope"], name=dids[1]["name"], state=OpenDataDIDState.PUBLIC)
        opendata.update_opendata_did(scope=dids[2]["scope"], name=dids[2]["name"], state=OpenDataDIDState.PUBLIC)
        # set number 4 to public, then suspended
        opendata.update_opendata_did(scope=dids[3]["scope"], name=dids[3]["name"], state=OpenDataDIDState.PUBLIC)
        opendata.update_opendata_did(scope=dids[3]["scope"], name=dids[3]["name"], state=OpenDataDIDState.SUSPENDED)

        opendata_dids = rucio_client.list_opendata_dids(public=True)["dids"]
        opendata_dids.sort(key=lambda x: x["name"])

        # only 2 and 3 should be present in response
        assert len(opendata_dids) == 2, "There should be only 2 public DIDs"
        for did_input, did_output in zip(dids[1:3], opendata_dids):
            assert did_output["scope"] == did_input["scope"], "Scope does not match"
            assert did_output["name"] == did_input["name"], "Name does not match"
            assert did_output["state"] == OpenDataDIDState.PUBLIC, "State does not match"

    def test_opendata_show_client(self, mock_scope, root_account, rucio_client):
        name = did_name_generator(did_type="dataset")

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)

        # Add it as open data
        opendata.add_opendata_did(scope=mock_scope, name=name)
        opendata_did = rucio_client.get_opendata_did(scope=str(mock_scope), name=name)

        assert opendata_did["scope"] == mock_scope, "Scope does not match"
        assert opendata_did["name"] == name, "Name does not match"
        assert opendata_did["state"] == OpenDataDIDState.DRAFT, "State does not match"

        assert opendata_did["doi"] is None, "DOI should be None"
        assert "files" not in opendata_did, "Files should not be present in the response"
        assert "meta" not in opendata_did, "Meta should not be present in the response"

        opendata_did = rucio_client.get_opendata_did(scope=str(mock_scope), name=name, files=True, meta=True, doi=True)
        assert opendata_did["doi"] is None, "DOI should still be None"
        assert "files" in opendata_did, "Files should be present in the response"
        assert "meta" in opendata_did, "Meta should be present in the response"
        meta = opendata_did["meta"]
        assert meta == {}, "'meta' should be empty"

    def test_opendata_public_show_client(self, mock_scope, root_account, rucio_client):
        name = did_name_generator(did_type="dataset")

        # Add it as a DID
        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)

        # Add it as open data
        opendata.add_opendata_did(scope=mock_scope, name=name)

        # fetch from the private endpoint
        opendata_did_from_private = rucio_client.get_opendata_did(scope=str(mock_scope), name=name, public=False)

        assert opendata_did_from_private["scope"] == mock_scope, "Scope does not match"
        assert opendata_did_from_private["name"] == name, "Name does not match"
        assert opendata_did_from_private["state"] == OpenDataDIDState.DRAFT, "State does not match"

        with pytest.raises(OpenDataDataIdentifierNotFound):
            # fetch from the public endpoint
            rucio_client.get_opendata_did(scope=str(mock_scope), name=name, public=True)

        # Update state to public
        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC)

        # Check we can still fetch it from the private endpoint
        assert opendata_did_from_private == rucio_client.get_opendata_did(scope=str(mock_scope), name=name,
                                                                          public=False)

        opendata_did_from_public = rucio_client.get_opendata_did(scope=str(mock_scope), name=name, public=True)

        assert opendata_did_from_public == opendata_did_from_private, "Public and private endpoints should return the same data for public DIDs"
