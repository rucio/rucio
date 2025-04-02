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

from rucio.common import exception
from rucio.common.exception import DataIdentifierAlreadyExists, DataIdentifierNotFound, FileAlreadyExists, \
    FileConsistencyMismatch, InvalidPath, ScopeNotFound, UnsupportedOperation, UnsupportedStatus
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import (
    add_did,
    add_did_to_followed,
    attach_dids,
    bulk_list_files,
    delete_dids,
    detach_dids,
    get_did,
    get_did_access_cnt,
    get_did_atime,
    get_metadata,
    get_users_following_did,
    list_dids,
    list_new_dids,
    remove_did_from_followed,
    set_metadata,
    set_new_dids,
    set_status,
    touch_dids,
)
from rucio.core.replica import add_replica, get_replica
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.util import json_implemented
from rucio.gateway import did, scope
from rucio.tests.common import did_name_generator, rse_name_generator, scope_name_generator

from rucio.core import opendata


def skip_without_json():
    if not json_implemented():
        pytest.skip("JSON support is not implemented in this database")


class TestOpenDataCore:

    def test_list_opendata_dids(self):
        for _ in opendata.list_opendata_dids():
            ...

        # public
        for _ in opendata.list_opendata_dids(state="P"):
            ...
