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
import time
from configparser import NoOptionError
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, parse_qsl, urlparse

import pytest
import requests
from dogpile.cache.api import NoValue

from rucio.common.config import config_add_section, config_get, config_get_bool, config_has_section, config_remove_option, config_set
from rucio.common.constants import OPENDATA_DID_STATE_LITERAL
from rucio.common.exception import (
    DataIdentifierNotFound,
    OpenDataDataIdentifierAlreadyExists,
    OpenDataDataIdentifierNotFound,
    OpenDataDuplicateDOI,
    OpenDataDuplicateRecordID,
    OpenDataError,
    OpenDataInvalidStateUpdate,
    ReplicaNotFound,
    ResourceTemporaryUnavailable,
)
from rucio.common.types import InternalScope
from rucio.common.utils import execute
from rucio.core import opendata
from rucio.core.did import add_did, set_status
from rucio.core.rse import add_rse_attribute
from rucio.db.sqla.constants import DIDType, OpenDataDIDState
from rucio.db.sqla.session import get_session
from rucio.db.sqla.util import json_implemented
from rucio.tests.common import auth, did_name_generator, headers, with_each_cli_renderer

skip_unsupported_json = pytest.mark.skipif(
    not json_implemented(),
    reason="JSON support is not implemented in this database"
)

skip_unsupported_dialect = pytest.mark.skipif(
    get_session().bind.dialect.name in ['oracle', 'sqlite'],
    reason=f"Unsupported dialect: {get_session().bind.dialect.name}"
)

OPENDATA_RSE_EXPRESSION = 'OpenData=True'


def _configure_opendata_rse_expression():
    if not config_has_section('opendata'):
        config_add_section('opendata')

    config_set(
        'opendata',
        'rse_expression',
        OPENDATA_RSE_EXPRESSION,
    )


@pytest.fixture(scope="module", autouse=True)
def module_setup():
    _configure_opendata_rse_expression()


class TestOpenDataCommon:
    def test_opendata_did_states(self):
        """
        Test that the OpenDataDIDState enum contains all expected states which are defined as a Literal in common/constants.py
        """

        opendata_did_state_from_common = set([state.upper() for state in OPENDATA_DID_STATE_LITERAL.__args__])
        opendata_did_state_from_enum = set([state.name for state in OpenDataDIDState])

        assert opendata_did_state_from_common == opendata_did_state_from_enum, "'OpenDataDIDState' enum does not match expected states from 'OPENDATA_DID_STATE_LITERAL'"

    def test_opendata_config(self):
        rse_expression = config_get('opendata', 'rse_expression')

        assert rse_expression == OPENDATA_RSE_EXPRESSION, f"'opendata.rse_expression' should be '{OPENDATA_RSE_EXPRESSION}'"


@pytest.mark.noparallel(reason="Changes in configuration values and race conditions")
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
        response = opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                                session=db_write_session)

        db_write_session.commit()

        state = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["state"]

        assert state == OpenDataDIDState.PUBLIC
        assert response["state_new"] == OpenDataDIDState.PUBLIC
        assert response["state_old"] == OpenDataDIDState.DRAFT

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

    def test_opendata_did_files_cache_key_length(self, mock_scope):
        cache_key = opendata._make_opendata_did_files_cache_key(
            mock_scope,
            "n" * 250,
            True,
        )

        assert len(cache_key.encode("utf-8")) <= 250

        without_download_urls = (
            opendata._make_opendata_did_files_cache_key(
                mock_scope,
                "n" * 250,
                False,
            )
        )

        assert cache_key != without_download_urls

    def test_opendata_did_files_cache_key_is_vo_aware(self):
        scope_vo1 = InternalScope("shared", vo="vo1")
        scope_vo2 = InternalScope("shared", vo="vo2")

        key_vo1 = opendata._make_opendata_did_files_cache_key(
            scope_vo1,
            "dataset",
            True,
        )
        key_vo2 = opendata._make_opendata_did_files_cache_key(
            scope_vo2,
            "dataset",
            True,
        )

        assert key_vo1 != key_vo2

    def test_opendata_did_files_cache_key_is_unambiguous(self):
        key_first = opendata._make_opendata_did_files_cache_key(
            InternalScope("a_b"),
            "c",
            True,
        )
        key_second = opendata._make_opendata_did_files_cache_key(
            InternalScope("a"),
            "b_c",
            True,
        )

        assert key_first != key_second

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

    def test_opendata_doi_duplicate(self, mock_scope, root_account, doi_factory, db_write_session):
        name_first = did_name_generator(did_type="dataset")
        name_second = did_name_generator(did_type="dataset")

        doi = doi_factory()

        for name in [name_first, name_second]:
            add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET,
                    session=db_write_session)
            opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        opendata.update_opendata_doi(scope=mock_scope, name=name_first, doi=doi, session=db_write_session)

        with pytest.raises(OpenDataDuplicateDOI):
            opendata.update_opendata_doi(scope=mock_scope, name=name_second, doi=doi, session=db_write_session)

    def test_opendata_record_id_update(self, mock_scope, root_account, db_write_session):
        name = did_name_generator(did_type="dataset")

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET,
                session=db_write_session)
        opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        record_id_first = 12345

        opendata.update_opendata_did(scope=mock_scope, name=name, record_id=record_id_first, session=db_write_session)

        db_write_session.commit()

        record_id_after = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["record_id"]

        assert record_id_after == record_id_first, f"Record ID should be updated to {record_id_first}, fetched from `get_opendata_did`"

        db_write_session.commit()

        record_id_after = opendata.get_opendata_record_id(scope=mock_scope, name=name, session=db_write_session)

        assert record_id_after == record_id_first, f"Record ID should be updated to {record_id_first}, fetched from `get_opendata_record_id`"

        record_id_second = 54321
        opendata.update_opendata_record_id(scope=mock_scope, name=name, record_id=record_id_second,
                                           session=db_write_session)

        db_write_session.commit()

        record_id_after = opendata.get_opendata_did(scope=mock_scope, name=name, session=db_write_session)["record_id"]

        assert record_id_after == record_id_second, f"Record ID should be updated (second time) to {record_id_second}, fetched from `get_opendata_did`"

        opendata.delete_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        db_write_session.commit()

    def test_opendata_record_id_duplicate(self, mock_scope, root_account, db_write_session):
        name_first = did_name_generator(did_type="dataset")
        name_second = did_name_generator(did_type="dataset")

        for name in [name_first, name_second]:
            add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET,
                    session=db_write_session)
            opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        record_id = 1337

        opendata.update_opendata_did(scope=mock_scope, name=name_first, record_id=record_id, session=db_write_session)

        db_write_session.commit()

        # delete it so we can use the record id in another did
        opendata.delete_opendata_did(scope=mock_scope, name=name_first, session=db_write_session)

        db_write_session.commit()

        # set previously used record id to another did
        opendata.update_opendata_did(scope=mock_scope, name=name_second, record_id=record_id, session=db_write_session)

        # add back previously deleted did so we can test for duplicates
        opendata.add_opendata_did(scope=mock_scope, name=name_first, session=db_write_session)

        with pytest.raises(OpenDataDuplicateRecordID):
            # using a record id that is in use by another open data did will throw
            opendata.update_opendata_did(scope=mock_scope, name=name_first, record_id=record_id,
                                         session=db_write_session)

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

    def test_opendata_dids_update_rule(self, mock_scope, root_account, vo, db_write_session, rse_factory):
        _, opendata_rse_id = rse_factory.make_posix_rse(session=db_write_session)
        add_rse_attribute(opendata_rse_id, key='OpenData', value=True, session=db_write_session)

        name = did_name_generator(did_type="dataset")

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET, session=db_write_session)
        opendata.add_opendata_did(scope=mock_scope, name=name, session=db_write_session)

        db_write_session.commit()

        set_status(scope=mock_scope, name=name, open=False, session=db_write_session)
        opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                     session=db_write_session)

        db_write_session.commit()

        try:
            config_set('opendata', 'rule_enable', 'False')
            # Remove `rule_rse_expression` to check exception when rule configuration is not present
            config_remove_option('opendata', 'rule_rse_expression')
            config_remove_option('opendata', 'rse_expression')

            rule_enable = config_get_bool("opendata", "rule_enable", raise_exception=False, default=False)
            assert rule_enable is False, "'opendata.rule_enable' should be False"

            response = opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                                    session=db_write_session)
            assert "rule" not in response or response[
                "rule"] is None, "No rule configuration is present, so no rule should be created"

            config_set('opendata', 'rule_enable', 'True')

            with pytest.raises(NoOptionError):
                # Because `rse_expression` and `rule_rse_expression` are not configured, rule creation fails
                opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                             session=db_write_session)

            config_set('opendata', 'rse_expression', OPENDATA_RSE_EXPRESSION)
            config_set('opendata', 'rule_rse_expression', OPENDATA_RSE_EXPRESSION)
            # do not set `rse_expression` yet, to check `rule_rse_expression` is enough
            config_set('opendata', 'rule_vo', vo)

            response = opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                                    session=db_write_session)
            rule = response["rule"]
            assert rule is not None, "Rule configuration is present, so a rule should be created"
            rule_first = rule

            response = opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.SUSPENDED,
                                                    session=db_write_session)
            assert "rule" not in response or response["rule"] is None, "Suspending a DID should not return a rule"

            response = opendata.update_opendata_did(scope=mock_scope, name=name, state=OpenDataDIDState.PUBLIC,
                                                    session=db_write_session)
            rule = response["rule"]
            assert rule is not None, "Rule configuration is present, so a rule should be created"
            assert rule == rule_first, "Rule should be the same as before because rules are not deleted when DID is suspended"

        finally:
            config_set('opendata', 'rule_enable', 'False')
            config_set('opendata', 'rse_expression', OPENDATA_RSE_EXPRESSION)
            config_set('opendata', 'rule_rse_expression', OPENDATA_RSE_EXPRESSION)

    def test_opendata_dids_show_files(self, mock_scope, root_account, db_write_session):
        name = did_name_generator(did_type="dataset")
        scope = mock_scope

        try:
            # Remove `rse_expression` to check exception when fetching files from Open Data RSEs
            config_remove_option('opendata', 'rse_expression')

            add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET,
                    session=db_write_session)
            opendata.add_opendata_did(scope=scope, name=name, session=db_write_session)

            db_write_session.commit()

            opendata_did = opendata.get_opendata_did(scope=scope, name=name, include_files=False,
                                                     session=db_write_session)

            assert opendata_did["scope"] == scope, "Scope does not match"
            assert opendata_did["name"] == name, "Name does not match"

            assert "files" not in opendata_did, "Files should not be present in the response"

            with pytest.raises(NoOptionError):
                opendata.get_opendata_did(scope=scope, name=name, include_files=True, session=db_write_session)

            config_set('opendata', 'rse_expression', OPENDATA_RSE_EXPRESSION)

            opendata_did = opendata.get_opendata_did(scope=scope, name=name, include_files=True,
                                                     session=db_write_session)

            assert opendata_did["scope"] == scope, "Scope does not match"
            assert opendata_did["name"] == name, "Name does not match"

            assert "files" in opendata_did, "Files should be present in the response"

        finally:
            config_set('opendata', 'rse_expression', OPENDATA_RSE_EXPRESSION)


class _FakeCacheRegion:
    """In-memory stand-in for the memcached-backed dogpile regions."""

    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key, NoValue())

    def set(self, key, value):
        self.store[key] = value


def _mock_eos_response(status_code=200, json_data=None):
    response = MagicMock()
    response.status_code = status_code
    if json_data is None:
        response.json.side_effect = ValueError("no json body")
    else:
        response.json.return_value = json_data
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(f"{status_code} error")
    else:
        response.raise_for_status.return_value = None
    return response


class TestOpenDataEOS:
    """
    Unit tests for the EOS download URL support. All network interactions are mocked.
    """

    eos_host = "eos.example.org"
    eos_version_payload = {"retc": "0", "stdOut": "EOS_SERVER_VERSION=5.2.31 EOS_SERVER_RELEASE=1", "stdErr": ""}
    eos_token = "zteos64:MDAwMDAyMmN4nOMSTVBLTC4RT09NT"

    @pytest.fixture(autouse=True)
    def isolate_eos_probe_cache(self, monkeypatch):
        monkeypatch.setattr(opendata, "EOS_PROBE_REGION", _FakeCacheRegion())
        monkeypatch.setattr(opendata, "EOS_PROBE_NEGATIVE_REGION", _FakeCacheRegion())

    def test_is_eos_host_positive(self):
        eos_host = f"{self.eos_host}:8444"

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=self.eos_version_payload),
        ) as mock_post:
            assert opendata._is_eos_host(eos_host) is True
            assert opendata._is_eos_host(eos_host) is True

        assert mock_post.call_count == 1
        assert mock_post.call_args[0][0] == (
            f"https://{self.eos_host}:8444"
            "/v1/eos/rest/gateway/version_cmd"
        )

    def test_is_eos_host_positive_integer_retc(self):
        payload = {"retc": 0, "stdOut": "EOS_SERVER_VERSION=5.2.31", "stdErr": ""}
        with patch("rucio.core.opendata.requests.post", return_value=_mock_eos_response(json_data=payload)):
            assert opendata._is_eos_host(self.eos_host) is True

    def test_is_eos_host_negative_http_error(self):
        with patch("rucio.core.opendata.requests.post", return_value=_mock_eos_response(status_code=404)) as mock_post:
            assert opendata._is_eos_host(self.eos_host) is False
            assert opendata._is_eos_host(self.eos_host) is False

        assert mock_post.call_count == 1, "Negative probe result should be cached"

    def test_is_eos_host_negative_unexpected_payload(self):
        payload = {"message": "I am not EOS"}
        with patch("rucio.core.opendata.requests.post", return_value=_mock_eos_response(json_data=payload)):
            assert opendata._is_eos_host(self.eos_host) is False

    def test_is_eos_host_unreachable(self):
        with patch(
            "rucio.core.opendata.requests.post",
            side_effect=requests.exceptions.ConnectionError("connection refused"),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._is_eos_host(self.eos_host)

    def test_eos_token_command(self):
        lifetime_seconds = 3600
        payload = {"retc": "0", "stdOut": f"{self.eos_token}\n", "stdErr": ""}
        with patch("rucio.core.opendata.requests.post",
                   return_value=_mock_eos_response(json_data=payload)) as mock_post:
            time_before = int(time.time())
            token = opendata._eos_grpc_gateway_token_command(eos_host=self.eos_host,
                                                             filename="/eos/opendata/experiment/file.root",
                                                             lifetime_seconds=lifetime_seconds)
            time_after = int(time.time())

        assert token == self.eos_token

        assert mock_post.call_args[0][0] == f"https://{self.eos_host}/v1/eos/rest/gateway/token_cmd"
        assert mock_post.call_args[1]["allow_redirects"] is False
        body = mock_post.call_args[1]["json"]
        assert body["path"] == "/eos/opendata/experiment/file.root"
        assert body["permission"] == "r"
        assert time_before + lifetime_seconds <= int(body["expires"]) <= time_after + lifetime_seconds

    def test_eos_token_command_host_with_port(self):
        eos_host = f"{self.eos_host}:8444"
        payload = {
            "retc": "0",
            "stdOut": self.eos_token,
            "stdErr": "",
        }

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=payload),
        ) as mock_post:
            token = opendata._eos_grpc_gateway_token_command(
                eos_host=eos_host,
                filename="/eos/opendata/file.root",
                lifetime_seconds=3600,
            )

        assert token == self.eos_token

        assert mock_post.call_args[0][0] == (
            f"https://{self.eos_host}:8444"
            "/v1/eos/rest/gateway/token_cmd"
        )

    def test_eos_token_command_empty_token(self):
        payload = {
            "retc": "0",
            "stdOut": "  \n",
            "stdErr": "",
        }

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=payload),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_eos_token_command_http_error(self):
        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(status_code=500),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_is_eos_host_tls_file_error(self):
        with patch(
            "rucio.core.opendata.requests.post",
            side_effect=OSError("CA file not found"),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._is_eos_host(self.eos_host)

    def test_eos_token_command_tls_file_error(self):
        with patch(
            "rucio.core.opendata.requests.post",
            side_effect=OSError("certificate file not found"),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_eos_token_command_unreachable(self):
        with patch(
            "rucio.core.opendata.requests.post",
            side_effect=requests.exceptions.ConnectionError("connection refused"),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_eos_token_command_nonzero_retc(self):
        payload = {
            "retc": -5,
            "stdOut": "zteos64:invalid-after-command-failure",
            "stdErr": "error: could not store token",
        }

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=payload),
        ):
            with pytest.raises(OpenDataError, match="retc=-5"):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_is_eos_host_temporary_http_error(self):
        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(status_code=503),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._is_eos_host(self.eos_host)

    def test_eos_token_command_non_temporary_http_error(self):
        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(status_code=404),
        ):
            with pytest.raises(OpenDataError):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_eos_token_command_rejects_diagnostic_output(self):
        payload = {
            "retc": "0",
            "stdOut": (
                f"{self.eos_token}\n"
                "warning: token requires approval"
            ),
            "stdErr": "",
        }

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=payload),
        ):
            with pytest.raises(OpenDataError):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    @pytest.mark.parametrize("retc", [None, "invalid"])
    def test_eos_token_command_invalid_retc(self, retc):
        payload = {
            "retc": retc,
            "stdOut": self.eos_token,
            "stdErr": "",
        }

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=payload),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_eos_token_command_missing_retc(self):
        payload = {
            "stdOut": self.eos_token,
            "stdErr": "",
        }

        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(json_data=payload),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._eos_grpc_gateway_token_command(
                    eos_host=self.eos_host,
                    filename="/eos/file.root",
                    lifetime_seconds=3600,
                )

    def test_is_eos_host_invalid_json(self):
        with patch(
            "rucio.core.opendata.requests.post",
            return_value=_mock_eos_response(status_code=200),
        ):
            with pytest.raises(ResourceTemporaryUnavailable):
                opendata._is_eos_host(self.eos_host)

    def test_generate_download_urls(self, monkeypatch):
        expected_eos_host = f"{self.eos_host}:8444"
        eos_uri = f"https://{self.eos_host}:8444//eos/opendata/experiment/file.root"
        uris = [
            eos_uri,
            "https://not-eos.example.org:443/other/path/file.root",
            "not a valid uri",
        ]

        requested_paths = []

        def fake_token_command(*, eos_host, filename, lifetime_seconds):
            assert eos_host == f"{self.eos_host}:8444"
            requested_paths.append(filename)
            return self.eos_token

        monkeypatch.setattr(opendata, "_is_eos_host", lambda host: host == expected_eos_host)
        monkeypatch.setattr(opendata, "_eos_grpc_gateway_token_command", fake_token_command)

        download_urls = opendata._generate_download_urls(uris)

        assert len(download_urls) == 1

        parsed = urlparse(download_urls[0])

        assert parsed.scheme == "https"
        assert parsed.hostname == self.eos_host
        assert parsed.port == 8444
        assert parsed.path == "//eos/opendata/experiment/file.root"
        assert parse_qs(parsed.query)["authz"] == [self.eos_token]

        # The double slash of the PFN must be collapsed in the path sent to EOS.
        assert requested_paths == ["/eos/opendata/experiment/file.root"]

    def test_generate_download_urls_uses_other_replica_after_temporary_failure(
        self,
        monkeypatch,
    ):
        first_uri = (
            f"https://first.{self.eos_host}:8444"
            "/eos/opendata/file.root"
        )
        second_uri = (
            f"https://second.{self.eos_host}:8444"
            "/eos/opendata/file.root"
        )

        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )

        def fake_token_command(*, eos_host, filename, lifetime_seconds):
            if eos_host == f"first.{self.eos_host}:8444":
                raise ResourceTemporaryUnavailable(
                    "temporary EOS failure"
                )
            return self.eos_token

        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fake_token_command,
        )

        download_urls = opendata._generate_download_urls(
            [first_uri, second_uri]
        )

        assert len(download_urls) == 1
        assert urlparse(download_urls[0]).hostname == (
            f"second.{self.eos_host}"
        )

    @pytest.mark.parametrize("failing_first", [True, False])
    def test_generate_download_urls_uses_healthy_replica_after_non_temporary_failure(
        self,
        monkeypatch,
        failing_first,
    ):
        failing_uri = (
            f"https://bad.{self.eos_host}:8444"
            "/eos/opendata/file.root"
        )
        working_uri = (
            f"https://good.{self.eos_host}:8444"
            "/eos/opendata/file.root"
        )

        uris = (
            [failing_uri, working_uri]
            if failing_first
            else [working_uri, failing_uri]
        )

        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )

        def fake_token_command(*, eos_host, filename, lifetime_seconds):
            if eos_host == f"bad.{self.eos_host}:8444":
                raise OpenDataError("non-retryable token failure")
            return self.eos_token

        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fake_token_command,
        )

        download_urls = opendata._generate_download_urls(uris)

        assert len(download_urls) == 1
        assert urlparse(download_urls[0]).hostname == (
            f"good.{self.eos_host}"
        )

    def test_generate_download_urls_preserves_ipv6_authority(self, monkeypatch):
        eos_uri = "https://[2001:db8::1]:8444//eos/opendata/file.root"

        probed_hosts = []
        token_hosts = []

        def fake_is_eos_host(host):
            probed_hosts.append(host)
            return True

        def fake_token_command(*, eos_host, filename, lifetime_seconds):
            token_hosts.append(eos_host)
            return self.eos_token

        monkeypatch.setattr(opendata, "_is_eos_host", fake_is_eos_host)
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fake_token_command,
        )

        download_urls = opendata._generate_download_urls([eos_uri])

        assert probed_hosts == ["[2001:db8::1]:8444"]
        assert token_hosts == ["[2001:db8::1]:8444"]

        parsed = urlparse(download_urls[0])
        assert parsed.hostname == "2001:db8::1"
        assert parsed.port == 8444
        assert parse_qs(parsed.query)["authz"] == [self.eos_token]

    @pytest.mark.parametrize("scheme", ["http", "https", "dav", "davs"])
    def test_generate_download_urls_supported_schemes(self, scheme, monkeypatch):
        eos_uri = (
            f"{scheme}://{self.eos_host}:8444"
            f"//eos/opendata/experiment/file.root"
        )

        probed_hosts = []
        token_requests = []

        def fake_is_eos_host(host):
            probed_hosts.append(host)
            return True

        def fake_token_command(*, eos_host, filename, lifetime_seconds):
            token_requests.append({
                "eos_host": eos_host,
                "filename": filename,
            })
            return self.eos_token

        monkeypatch.setattr(opendata, "_is_eos_host", fake_is_eos_host)
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fake_token_command,
        )

        download_urls = opendata._generate_download_urls([eos_uri])

        assert len(download_urls) == 1

        parsed = urlparse(download_urls[0])

        assert parsed.scheme == scheme
        assert parsed.hostname == self.eos_host
        assert parsed.port == 8444
        assert parsed.path == "//eos/opendata/experiment/file.root"
        assert parse_qs(parsed.query)["authz"] == [self.eos_token]

        assert probed_hosts == [
            f"{self.eos_host}:8444"
        ]

        assert token_requests == [
            {
                "eos_host": f"{self.eos_host}:8444",
                "filename": "/eos/opendata/experiment/file.root",
            }
        ]

    def test_generate_download_urls_preserves_query_and_fragment(
        self,
        monkeypatch,
    ):
        token = "token+value"
        eos_uri = (
            f"https://{self.eos_host}:8444"
            "/eos/opendata/file.root"
            "?source=a&source=b&flag#part"
        )

        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            lambda **kwargs: token,
        )

        download_urls = opendata._generate_download_urls([eos_uri])

        assert len(download_urls) == 1

        parsed = urlparse(download_urls[0])

        # Verify that the existing query is preserved verbatim.
        assert parsed.query.startswith(
            "source=a&source=b&flag&authz="
        )

        # Verify its decoded semantics as well.
        assert parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ) == [
            ("source", "a"),
            ("source", "b"),
            ("flag", ""),
            ("authz", token),
        ]

        assert parsed.fragment == "part"

    def test_generate_download_urls_temporary_token_failure(self, monkeypatch):
        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )

        def fail_token_command(**kwargs):
            raise ResourceTemporaryUnavailable("temporary EOS failure")

        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fail_token_command,
        )

        eos_uri = f"https://{self.eos_host}:8444/eos/file.root"

        with pytest.raises(ResourceTemporaryUnavailable):
            opendata._generate_download_urls([eos_uri])

    def test_generate_download_urls_reuses_equivalent_eos_token(
        self,
        monkeypatch,
    ):
        uris = [
            (
                f"{scheme}://{self.eos_host}:8444"
                "//eos/opendata/file.root"
            )
            for scheme in ["http", "https", "dav", "davs"]
        ]

        probed_hosts = []
        token_requests = []

        def fake_is_eos_host(host):
            probed_hosts.append(host)
            return True

        def fake_token_command(
            *,
            eos_host,
            filename,
            lifetime_seconds,
        ):
            token_requests.append((eos_host, filename))
            return self.eos_token

        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            fake_is_eos_host,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fake_token_command,
        )

        download_urls = opendata._generate_download_urls(uris)

        # Preserve all supported protocol alternatives.
        assert len(download_urls) == 4
        assert {
            urlparse(url).scheme
            for url in download_urls
        } == {"http", "https", "dav", "davs"}

        # Probe and token generation happen once for the common scope.
        assert probed_hosts == [
            f"{self.eos_host}:8444"
        ]
        assert token_requests == [
            (
                f"{self.eos_host}:8444",
                "/eos/opendata/file.root",
            )
        ]

        for url in download_urls:
            assert parse_qs(urlparse(url).query)["authz"] == [
                self.eos_token
            ]

    def test_generate_download_urls_propagates_non_temporary_failure(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )

        def fail_token_command(**kwargs):
            raise OpenDataError("EOS command rejected")

        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fail_token_command,
        )

        uri = f"https://{self.eos_host}:8444/eos/file.root"

        with pytest.raises(OpenDataError, match="EOS command rejected"):
            opendata._generate_download_urls([uri])

    def test_extract_disk_uris_filters_non_disk_replicas(self):
        disk_uri = (
            "https://disk.example.org:8444"
            "//eos/file.root"
        )
        tape_uri = (
            "https://tape.example.org:8444"
            "//eos/file.root"
        )

        replicas = [
            {
                "pfns": {
                    disk_uri: {"type": "DISK"},
                    tape_uri: {"type": "TAPE"},
                }
            }
        ]

        assert opendata._extract_disk_uris(replicas) == [
            disk_uri
        ]
        assert opendata._extract_disk_uris(
            [
                {
                    "pfns": {
                        tape_uri: {"type": "TAPE"},
                    }
                }
            ]
        ) == []

    def test_get_opendata_did_files_download_url_generation_failure(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_name = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        db_write_session.commit()

        https_uri = (
            f"https://{self.eos_host}:8444"
            "//eos/opendata/experiment/file.root"
        )

        def fake_list_files(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "bytes": 42,
                "adler32": "deadbeef",
            }

        def fake_list_replicas(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "pfns": {
                    https_uri: {"type": "DISK"},
                },
            }

        def fail_token_command(**kwargs):
            raise ResourceTemporaryUnavailable(
                "temporary EOS token failure"
            )

        monkeypatch.setattr(
            opendata,
            "list_files",
            fake_list_files,
        )
        monkeypatch.setattr(
            opendata,
            "list_replicas",
            fake_list_replicas,
        )
        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fail_token_command,
        )

        with pytest.raises(ResourceTemporaryUnavailable):
            opendata.get_opendata_did_files(
                scope=mock_scope,
                name=name,
                include_download_urls=True,
                session=db_write_session,
            )

    def test_generate_download_urls_skips_root_eos_uri(self, monkeypatch):
        eos_uri = f"root://{self.eos_host}:1094//eos/opendata/file.root"

        def unexpected_eos_probe(host):
            pytest.fail(
                "EOS probing must not run for unsupported root:// replicas"
            )

        def unexpected_token_request(**kwargs):
            pytest.fail(
                "EOS token generation must not run for unsupported root:// replicas"
            )

        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            unexpected_eos_probe,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            unexpected_token_request,
        )

        download_urls = opendata._generate_download_urls([eos_uri])

        assert download_urls == []

    def test_get_opendata_did_files_download_urls_only_root(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_name = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        db_write_session.commit()

        root_uri = f"root://{self.eos_host}:1094//eos/opendata/file.root"

        def fake_list_files(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "bytes": 42,
                "adler32": "deadbeef",
            }

        def fake_list_replicas(*args, **kwargs):
            if kwargs.get("schemes") == ["http", "https", "dav", "davs"]:
                yield {
                    "scope": mock_scope,
                    "name": file_name,
                    "pfns": {},
                }
            else:
                yield {
                    "scope": mock_scope,
                    "name": file_name,
                    "pfns": {
                        root_uri: {"type": "DISK"},
                    },
                }

        monkeypatch.setattr(opendata, "list_files", fake_list_files)
        monkeypatch.setattr(opendata, "list_replicas", fake_list_replicas)

        with pytest.raises(
            ReplicaNotFound,
            match="No HTTP\\(S\\) or DAV\\(S\\) DISK replica URI available",
        ):
            opendata.get_opendata_did_files(
                scope=mock_scope,
                name=name,
                include_download_urls=True,
                session=db_write_session,
            )

    def test_get_opendata_did_files_download_urls(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_name = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        db_write_session.commit()

        root_uri = f"root://{self.eos_host}:1094//eos/opendata/experiment/file.root"
        https_uri = f"https://{self.eos_host}:8444//eos/opendata/experiment/file.root"
        expected_eos_host = f"{self.eos_host}:8444"

        requested_schemes = []

        def fake_list_files(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "bytes": 42,
                "adler32": "deadbeef",
            }

        def fake_list_replicas(*args, **kwargs):
            schemes = kwargs.get("schemes")
            requested_schemes.append(schemes)

            if schemes == ["http", "https", "dav", "davs"]:
                yield {
                    "scope": mock_scope,
                    "name": file_name,
                    "pfns": {
                        https_uri: {"type": "DISK"},
                    },
                }
            else:
                yield {
                    "scope": mock_scope,
                    "name": file_name,
                    "pfns": {
                        root_uri: {"type": "DISK"},
                    },
                }

        monkeypatch.setattr(opendata, "list_files", fake_list_files)
        monkeypatch.setattr(opendata, "list_replicas", fake_list_replicas)
        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: host == expected_eos_host,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            lambda **kwargs: self.eos_token,
        )

        result = opendata.get_opendata_did_files(
            scope=mock_scope,
            name=name,
            include_download_urls=True,
            session=db_write_session,
        )

        assert len(result["files"]) == 1

        file = result["files"][0]

        assert file["uris"] == [root_uri]

        assert len(file["download_urls"]) == 1

        parsed = urlparse(file["download_urls"][0])

        assert parsed.scheme == "https"
        assert parsed.hostname == self.eos_host
        assert parsed.port == 8444
        assert parsed.path == "//eos/opendata/experiment/file.root"
        assert parse_qs(parsed.query)["authz"] == [self.eos_token]

        assert ["http", "https", "dav", "davs"] in requested_schemes

    def test_get_opendata_did_files_without_download_urls(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_name = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )
        db_write_session.commit()

        root_uri = (
            f"root://{self.eos_host}:1094"
            f"//eos/opendata/{file_name}"
        )

        list_replicas_calls = []

        def fake_list_files(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "bytes": 42,
                "adler32": "deadbeef",
            }

        def fake_list_replicas(*args, **kwargs):
            list_replicas_calls.append(kwargs)

            for did in kwargs["dids"]:
                yield {
                    "scope": did["scope"],
                    "name": did["name"],
                    "pfns": {
                        root_uri: {"type": "DISK"},
                    },
                }

        def unexpected_eos_probe(host):
            pytest.fail(
                "EOS probing must not run when "
                "include_download_urls=False"
            )

        def unexpected_token_request(**kwargs):
            pytest.fail(
                "EOS token generation must not run when "
                "include_download_urls=False"
            )

        monkeypatch.setattr(
            opendata,
            "list_files",
            fake_list_files,
        )
        monkeypatch.setattr(
            opendata,
            "list_replicas",
            fake_list_replicas,
        )
        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            unexpected_eos_probe,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            unexpected_token_request,
        )

        result = opendata.get_opendata_did_files(
            scope=mock_scope,
            name=name,
            include_download_urls=False,
            session=db_write_session,
        )

        assert len(list_replicas_calls) == 1
        assert list_replicas_calls[0].get("schemes") is None

        assert result["files"][0]["uris"] == [root_uri]
        assert "download_urls" not in result["files"][0]

    def test_get_opendata_did_files_batches_replica_resolution(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_names = [
            did_name_generator(did_type="file")
            for _ in range(3)
        ]

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        db_write_session.commit()

        def fake_list_files(*args, **kwargs):
            for file_name in file_names:
                yield {
                    "scope": mock_scope,
                    "name": file_name,
                    "bytes": 42,
                    "adler32": "deadbeef",
                }

        list_replicas_calls = []

        def fake_list_replicas(*args, **kwargs):
            dids = kwargs["dids"]
            schemes = kwargs.get("schemes")

            list_replicas_calls.append({
                "dids": list(dids),
                "schemes": schemes,
                "resolve_archives": kwargs.get("resolve_archives"),
            })

            for did in dids:
                if schemes == ["http", "https", "dav", "davs"]:
                    uri = (
                        f"https://{self.eos_host}:8444"
                        f"//eos/opendata/{did['name']}"
                    )
                else:
                    uri = (
                        f"root://{self.eos_host}:1094"
                        f"//eos/opendata/{did['name']}"
                    )

                yield {
                    "scope": did["scope"],
                    "name": did["name"],
                    "pfns": {
                        uri: {"type": "DISK"},
                    },
                }

        monkeypatch.setattr(opendata, "list_files", fake_list_files)
        monkeypatch.setattr(opendata, "list_replicas", fake_list_replicas)
        monkeypatch.setattr(opendata, "_is_eos_host", lambda host: True)
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            lambda **kwargs: self.eos_token,
        )

        result = opendata.get_opendata_did_files(
            scope=mock_scope,
            name=name,
            include_download_urls=True,
            session=db_write_session,
        )

        assert len(result["files"]) == 3

        # Exactly one batch for regular replicas and one for download replicas.
        assert len(list_replicas_calls) == 2

        regular_call = list_replicas_calls[0]
        download_call = list_replicas_calls[1]

        assert regular_call["schemes"] is None
        assert download_call["schemes"] == [
            "http",
            "https",
            "dav",
            "davs",
        ]

        assert len(regular_call["dids"]) == 3
        assert len(download_call["dids"]) == 3
        assert download_call["resolve_archives"] is False

        assert {
            did["name"] for did in regular_call["dids"]
        } == set(file_names)

        assert {
            did["name"] for did in download_call["dids"]
        } == set(file_names)

        for file in result["files"]:
            assert file["uris"] == [
                f"root://{self.eos_host}:1094"
                f"//eos/opendata/{file['name']}"
            ]

            assert len(file["download_urls"]) == 1

            parsed = urlparse(file["download_urls"][0])

            assert parsed.path == f"//eos/opendata/{file['name']}"
            assert parse_qs(parsed.query)["authz"] == [self.eos_token]

    @pytest.mark.parametrize(
        "uri",
        [
            "https://eos.example.org:notaport/eos/file.root",
            "https://eos.example.org:99999/eos/file.root",
        ],
    )
    def test_generate_download_urls_skips_invalid_port(self, uri, monkeypatch):
        token_called = False

        def fake_token_command(**kwargs):
            nonlocal token_called
            token_called = True
            return self.eos_token

        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            fake_token_command,
        )

        download_urls = opendata._generate_download_urls([uri])

        assert download_urls == []
        assert token_called is False

    def test_get_opendata_did_files_no_disk_uri_without_download_urls(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_name = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        db_write_session.commit()

        def fake_list_files(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "bytes": 42,
                "adler32": "deadbeef",
            }

        def fake_list_replicas(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "pfns": {},
            }

        monkeypatch.setattr(
            opendata,
            "list_files",
            fake_list_files,
        )
        monkeypatch.setattr(
            opendata,
            "list_replicas",
            fake_list_replicas,
        )

        result = opendata.get_opendata_did_files(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        assert len(result["files"]) == 1
        # Missing regular replicas must not fail a file listing when
        # tokenized download URLs were not requested.
        assert result["files"][0]["uris"] == []
        assert "download_urls" not in result["files"][0]

    def test_get_opendata_did_files_ignores_legacy_cache(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        cache = _FakeCacheRegion()
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        file_name = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )

        db_write_session.commit()

        legacy_key = f"opendata_did_files_{mock_scope}_{name}_dl_True"

        cache.set(
            legacy_key,
            [
                {
                    "scope": mock_scope,
                    "name": file_name,
                    "uris": [],
                    "download_urls": [
                        "https://old.example/file?token=legacy"
                    ],
                }
            ],
        )

        https_uri = (
            f"https://{self.eos_host}:8444"
            "//eos/opendata/file.root"
        )

        def fake_list_files(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "bytes": 42,
                "adler32": "deadbeef",
            }

        def fake_list_replicas(*args, **kwargs):
            yield {
                "scope": mock_scope,
                "name": file_name,
                "pfns": {
                    https_uri: {"type": "DISK"},
                },
            }

        monkeypatch.setattr(opendata, "REGION", cache)
        monkeypatch.setattr(opendata, "list_files", fake_list_files)
        monkeypatch.setattr(opendata, "list_replicas", fake_list_replicas)
        monkeypatch.setattr(
            opendata,
            "_is_eos_host",
            lambda host: True,
        )
        monkeypatch.setattr(
            opendata,
            "_eos_grpc_gateway_token_command",
            lambda **kwargs: self.eos_token,
        )

        result = opendata.get_opendata_did_files(
            scope=mock_scope,
            name=name,
            use_cache=True,
            include_download_urls=True,
            session=db_write_session,
        )

        assert result["cache_hit"] is False

        assert len(result["files"]) == 1

        file = result["files"][0]

        assert file["uris"] == [https_uri]

        assert len(file["download_urls"]) == 1

        parsed = urlparse(file["download_urls"][0])
        query = parse_qs(parsed.query)

        assert query["authz"] == [self.eos_token]
        assert "token" not in query

    def test_get_opendata_did_files_validates_all_download_uris_before_token_generation(
        self,
        mock_scope,
        monkeypatch,
        did_factory,
        db_write_session,
    ):
        _configure_opendata_rse_expression()
        dataset = did_factory.make_dataset(
            scope=mock_scope,
            session=db_write_session,
        )

        name = dataset["name"]
        first_file = did_name_generator(did_type="file")
        second_file = did_name_generator(did_type="file")

        opendata.add_opendata_did(
            scope=mock_scope,
            name=name,
            session=db_write_session,
        )
        db_write_session.commit()

        def fake_list_files(*args, **kwargs):
            for file_name in [first_file, second_file]:
                yield {
                    "scope": mock_scope,
                    "name": file_name,
                    "bytes": 42,
                    "adler32": "deadbeef",
                }

        def fake_list_replicas(*args, **kwargs):
            download_lookup = kwargs.get("schemes") is not None

            for did in kwargs["dids"]:
                if download_lookup:
                    pfns = (
                        {
                            f"https://{self.eos_host}:8444"
                            f"/eos/{did['name']}": {"type": "DISK"}
                        }
                        if did["name"] == first_file
                        else {}
                    )
                else:
                    pfns = {}

                yield {
                    "scope": did["scope"],
                    "name": did["name"],
                    "pfns": pfns,
                }

        def unexpected_download_generation(uris):
            pytest.fail(
                "Download URLs must not be generated before "
                "all files have been validated"
            )

        monkeypatch.setattr(opendata, "list_files", fake_list_files)
        monkeypatch.setattr(opendata, "list_replicas", fake_list_replicas)
        monkeypatch.setattr(
            opendata,
            "_generate_download_urls",
            unexpected_download_generation,
        )

        with pytest.raises(
            ReplicaNotFound,
            match="No HTTP\\(S\\) or DAV\\(S\\) DISK replica URI available",
        ):
            opendata.get_opendata_did_files(
                scope=mock_scope,
                name=name,
                include_download_urls=True,
                session=db_write_session,
            )


@pytest.mark.noparallel(reason="Changes in configuration values and race conditions")
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

        if not config_has_section('opendata'):
            config_add_section('opendata')

        config_set('opendata', 'rse_expression', OPENDATA_RSE_EXPRESSION)

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
        assert opendata_did["record_id"] is None, "Record ID should be None"
        assert "files" not in opendata_did, "Files should not be present in the response"
        assert "meta" not in opendata_did, "Meta should not be present in the response"

        opendata_did = rucio_client.get_opendata_did(scope=scope, name=name,
                                                     include_files=True, include_metadata=True,
                                                     include_doi=True, include_record_id=True)
        assert opendata_did["doi"] is None, "DOI should still be None"
        assert opendata_did["record_id"] is None, "Record ID should still be None"
        assert "files" in opendata_did, "Files should be present in the response"
        assert "meta" in opendata_did, "Meta should be present in the response"
        meta = opendata_did["meta"]
        assert meta == {}, "'meta' should be empty"


@pytest.mark.noparallel(reason="Changes in configuration values and race conditions")
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

    def test_opendata_api_get_download_urls(self, rest_client, auth_token, root_account, mock_scope):
        name = did_name_generator(did_type="dataset")
        endpoint = f"{self.api_endpoint}/{mock_scope}/{name}"
        request_headers = headers(auth(auth_token))

        add_did(scope=mock_scope, name=name, account=root_account, did_type=DIDType.DATASET)

        response = rest_client.post(
            endpoint,
            headers=request_headers,
        )
        assert response.status_code == 201, f"Expected 201 Created, got {response.status_code}"

        try:
            response = rest_client.get(
                f"{endpoint}?files=1&download_urls=1",
                headers=request_headers,
            )
            assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
            assert "files" in response.json, "Files should be present in the response"

            # Download URLs require the file list to be requested.
            response = rest_client.get(
                f"{endpoint}?download_urls=1",
                headers=request_headers,
            )
            assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"
        finally:
            rest_client.delete(
                endpoint,
                headers=request_headers,
            )

    @pytest.mark.parametrize("public", [False, True])
    def test_opendata_api_temporary_failure_returns_503(
        self,
        rest_client,
        request,
        mock_scope,
        public,
    ):
        name = did_name_generator(did_type="dataset")
        base_endpoint = (
            self.api_endpoint_public
            if public
            else self.api_endpoint
        )
        endpoint = (
            f"{base_endpoint}/{mock_scope}/{name}"
            "?files=1&download_urls=1"
        )

        request_kwargs = {}
        if not public:
            request_kwargs["headers"] = headers(
                auth(request.getfixturevalue("auth_token"))
            )

        with patch(
            "rucio.gateway.opendata.get_opendata_did",
            side_effect=ResourceTemporaryUnavailable(
                "temporary EOS failure"
            ),
        ):
            response = rest_client.get(
                endpoint,
                **request_kwargs,
            )

        assert response.status_code == 503

    @pytest.mark.parametrize("public", [False, True])
    @pytest.mark.parametrize(
        "error_class, expected_status",
        [
            (OpenDataDataIdentifierNotFound, 404),
            (ReplicaNotFound, 404),
            (OpenDataError, 500),
        ],
    )
    def test_opendata_api_download_failure_status(
        self,
        rest_client,
        request,
        mock_scope,
        public,
        error_class,
        expected_status,
    ):
        base_endpoint = (
            self.api_endpoint_public
            if public
            else self.api_endpoint
        )

        endpoint = (
            f"{base_endpoint}/{mock_scope}/test"
            "?files=1&download_urls=1"
        )

        request_kwargs = {}
        if not public:
            request_kwargs["headers"] = headers(
                auth(request.getfixturevalue("auth_token"))
            )

        with patch(
            "rucio.gateway.opendata.get_opendata_did",
            side_effect=error_class("download failure"),
        ):
            response = rest_client.get(
                endpoint,
                **request_kwargs,
            )

        assert response.status_code == expected_status


@pytest.mark.noparallel(reason="Changes in configuration values and race conditions")
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
        ("list", {"--help", "--state", "--public", "--short"}),
        ("show", {"--help", "--meta", "--files", "--public", "--download-urls"}),
        ("update", {"--help", "--meta", "--state", "--doi", "--record-id"}),
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

    def test_opendata_cli_show_download_urls_requires_files(self, mock_scope):
        name = did_name_generator(did_type="dataset")
        cmd = f"rucio opendata did show {mock_scope}:{name} --download-urls"
        exitcode, _, stderr = execute(cmd)
        assert exitcode != 0, f"Command '{cmd}' should have failed but succeeded"
        assert "--files" in stderr, f"Error message should mention the --files requirement, got: {stderr.strip()}"

    @with_each_cli_renderer
    def test_opendata_cli_add_show_list_remove(self, mock_scope, file_config_mock):
        exitcode, stdout, stderr = execute("rucio opendata did list")
        assert exitcode == 0, f"Command 'rucio opendata list' failed with error: {stderr.strip()}"
        assert "ERROR" not in stderr.upper(), f"Command 'rucio opendata list' failed with error: {stderr.strip()}"

        name = did_name_generator(did_type="dataset")

        exitcode, stdout, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 1, f"Expected failure when adding bad DID: {stderr.strip()}"
        assert "Data identifier not found" in stderr

        exitcode, stdout, stderr = execute(f"rucio opendata did remove {mock_scope}:{name}")
        assert exitcode == 1, f"Expected failure when removing unregistered DID: {stderr.strip()}"
        assert "Data identifier not found in the open data catalog" in stderr

        exitcode, _, stderr = execute(f"rucio did add --type dataset {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to add dataset: {stderr.strip()}"

        exitcode, _, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to add opendata DID: {stderr.strip()}"

        exitcode, stdout, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 1, f"Expected failure when adding existing opendata DID: {stderr.strip()}"
        assert "Data identifier already exists in the open data catalog" in stderr

        exitcode, _, stderr = execute(f"rucio opendata did show {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to show opendata DID: {stderr.strip()}"

        exitcode, stdout, stderr = execute("rucio opendata did list")
        assert exitcode == 0, f"Failed to list opendata: {stderr.strip()}"
        assert f"{name}" in stdout, f"Expected {mock_scope}:{name} in opendata list"

        # Using the --short option the output should be the same regardless of rich client being used
        exitcode, stdout, stderr = execute("rucio opendata did list --short")
        assert exitcode == 0, f"Failed to list opendata with short option: {stderr.strip()}"
        lines = [line.strip() for line in stdout.split("\n") if line.strip()]
        pattern = re.compile(r"^[^:]+:.+$")
        assert all(pattern.match(line) for line in lines), "All lines should follow the scope:name pattern"
        assert f"{mock_scope}:{name}" in lines, f"Expected {mock_scope}:{name} in opendata list with short option"

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

    @skip_unsupported_dialect
    def test_opendata_cli_update_delete(self, mock_scope, doi_factory):
        name = did_name_generator(did_type="dataset")

        # Add Rucio DID
        exitcode, _, stderr = execute(f"rucio did add {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to add DID: {stderr.strip()}"

        # Add DID to Open Data
        exitcode, _, stderr = execute(f"rucio opendata did add {mock_scope}:{name}")
        assert exitcode == 0, f"Failed to add Open Data DID: {stderr.strip()}"

        # Update the Record ID (using a hash of the name to avoid collisions)
        record_id = abs(hash(name)) % 10 ** 8
        exitcode, _, stderr = execute(f"rucio opendata did update {mock_scope}:{name} --record-id {record_id}")
        assert exitcode == 0, f"Failed to update Open Data DID: {stderr.strip()}"

        # Update the DOI
        doi = doi_factory()
        exitcode, _, stderr = execute(f"rucio opendata did update {mock_scope}:{name} --doi {doi}")
        assert exitcode == 0, f"Failed to update Open Data DID DOI: {stderr.strip()}"

        # Update the Open Data metadata
        meta_json = '{"key": "value", "number": 123}'
        exitcode, _, stderr = execute(f"rucio opendata did update {mock_scope}:{name} --meta '{meta_json}'")
        assert exitcode == 0, f"Failed to update Open Data DID metadata: {stderr.strip()}"

        # Close the DID before state updates
        exitcode, _, stderr = execute(f"rucio did update {mock_scope}:{name} --close")
        assert exitcode == 0, f"Failed to close DID: {stderr.strip()}"

        # Update the state to public
        exitcode, _, stderr = execute(f"rucio opendata did update {mock_scope}:{name} --state public")
        assert exitcode == 0, f"Failed to update Open Data DID state to public: {stderr.strip()}"

        # Update the state to suspended
        exitcode, _, stderr = execute(f"rucio opendata did update {mock_scope}:{name} --state suspended")
        assert exitcode == 0, f"Failed to update Open Data DID state to suspended: {stderr.strip()}"
