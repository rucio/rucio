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

"""Helpers shared across Alembic migrations."""

from .ddl_helpers import (
    add_column,
    alter_column,
    create_check_constraint,
    create_index,
    create_primary_key,
    create_table,
    create_unique_constraint,
    drop_column,
    drop_constraint,
    drop_current_primary_key,
    drop_index,
    drop_table,
    get_current_dialect,
    get_effective_schema,
    get_identifier_preparer,
    get_migration_context,
    is_current_dialect,
    qualify_index,
    qualify_table,
    quote_identifier,
    rename_table,
    try_drop_constraint,
    try_drop_index,
)
from .enum_ddl_helpers import (
    drop_enum_sql,
    render_enum_name,
)

__all__ = [
    "add_column",
    "alter_column",
    "create_check_constraint",
    "create_index",
    "create_primary_key",
    "create_table",
    "create_unique_constraint",
    "drop_column",
    "drop_constraint",
    "drop_current_primary_key",
    "drop_enum_sql",
    "drop_index",
    "drop_table",
    "get_current_dialect",
    "get_effective_schema",
    "get_identifier_preparer",
    "get_migration_context",
    "is_current_dialect",
    "qualify_index",
    "qualify_table",
    "quote_identifier",
    "rename_table",
    "render_enum_name",
    "try_drop_constraint",
    "try_drop_index",
]
