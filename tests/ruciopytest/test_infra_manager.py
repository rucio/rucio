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

"""Database reset tests for :class:`infra_manager.InfraManager`.

``rucio.db.sqla.util`` is replaced by a stub, so no database is needed.
"""

import sys
from types import SimpleNamespace

import pytest

from tests.ruciopytest.infra_manager import InfraManager
from tests.ruciopytest.profiles import resolve_profile


@pytest.fixture
def db_util(monkeypatch):
    calls = []
    stub = SimpleNamespace(
        drop_orm_tables=lambda: calls.append("drop_orm_tables"),
        purge_db=lambda: calls.append("purge_db"),
    )
    monkeypatch.setitem(sys.modules, "rucio.db.sqla.util", stub)
    return calls


def test_oracle_drops_only_rucio_tables(db_util) -> None:
    """Oracle's ``system`` schema also holds Oracle's own tables: never purge it."""
    InfraManager(resolve_profile("remote_dbs", "oracle"))._purge_database()
    assert db_util == ["drop_orm_tables"]


@pytest.mark.parametrize("rdbms", [None, "postgres14", "mysql8"])
def test_other_backends_purge_the_schema(db_util, rdbms) -> None:
    InfraManager(resolve_profile("remote_dbs", rdbms))._purge_database()
    assert db_util == ["purge_db"]
