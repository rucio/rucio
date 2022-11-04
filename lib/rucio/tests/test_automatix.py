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

import json
import os
from random import choice
from string import ascii_uppercase
import tempfile

import pytest

from rucio.common.config import config_add_section, config_has_section, config_set, config_remove_option
from rucio.common.types import InternalScope
from rucio.core.did import list_dids, list_files, get_metadata
from rucio.core.scope import add_scope
from rucio.daemons.automatix.automatix import automatix
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import scope_name_generator


@pytest.mark.noparallel(reason='changes global configuration value')
def test_automatix(vo, root_account, rse_factory):
    """Automatix: Test the automatix daemon"""
    scope = scope_name_generator()
    add_scope(scope=InternalScope(scope, vo), account=root_account)
    if not config_has_section("automatix"):
        config_add_section("automatix")
    rse, rse_id = rse_factory.make_posix_rse()
    config_set("automatix", "rses", rse)
    config_set("automatix", "scope", scope)
    if os.environ.get("POLICY") == "belleii":
        config_set(
            "automatix",
            "dataset_pattern",
            "did_prefix/version/project/date/campaign/release/datatype",
        )
        config_set("automatix", "file_pattern", "dsn/uuid")
        config_set("automatix", "did_prefix", "/belle/ddm/tests")
        config_set("automatix", "separator", "/")

    project = ''.join(choice(ascii_uppercase) for _ in range(8))
    test_dict = {
        "type1": {
            "probability": 100,
            "nbfiles": 2,
            "filesize": 1000000,
            "metadata": {"project": project, "datatype": "AOD", "prod_step": "recon"},
        }
    }
    with tempfile.NamedTemporaryFile("w") as file_:
        json.dump(test_dict, file_)
        file_.flush()
        automatix(
            inputfile=file_.name,
            sleep_time=10,
            once=True,
        )
        dids = [
            did
            for did in list_dids(
                scope=InternalScope(scope, vo),
                filters={"project": project},
                did_type="collection",
            )
        ]
        assert len(dids) == 1
        meta = get_metadata(InternalScope(scope, vo), dids[0])
        assert meta["project"] == project
        assert meta["datatype"] == 'AOD'
        assert meta["prod_step"] == 'recon'
        rse_info = rsemgr.get_rse_info(rse, vo)
        files = [file_ for file_ in list_files(InternalScope(scope, vo), dids[0])]
        for file_ in files:
            file_["scope"] = file_["scope"].external
        status, file_dict = rsemgr.exists(rse_info, files)
        assert status
        for file_ in files:
            assert file_dict["%s:%s" % (file_["scope"], file_["name"])] is True
    config_remove_option("automatix", "rses")
    config_remove_option("automatix", "scope")
