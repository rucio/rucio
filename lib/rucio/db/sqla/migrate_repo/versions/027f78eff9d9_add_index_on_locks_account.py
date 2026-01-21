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

"""add_index_on_locks_account"""    # noqa: D`400, D415

from alembic import context
from alembic.op import create_index, drop_index

# Alembic revision identifiers
revision = '027f78eff9d9'
down_revision = '3b943000da18'


def upgrade():
    """Upgrade schema."""
    dialect_name = context.get_context().dialect.name
    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else None

    if dialect_name in ['oracle', 'postgresql']:
        create_index('LOCKS_ACCOUNT_IDX', 'locks', ['account'], schema=schema)


def downgrade():
    """Downgrade schema."""
    dialect_name = context.get_context().dialect.name
    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else None

    if dialect_name in ['oracle', 'postgresql']:
        drop_index('LOCKS_ACCOUNT_IDX', 'locks', schema=schema)
