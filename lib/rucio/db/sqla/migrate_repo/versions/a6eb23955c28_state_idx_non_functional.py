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

""" state idx non functional """

from alembic.op import create_index, drop_index, execute

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect

# Alembic revision identifiers
revision = 'a6eb23955c28'
down_revision = 'fb28a95fe288'


def upgrade():
    """
    Upgrade the database to this revision
    """

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""
    if is_current_dialect('oracle', 'postgresql'):
        execute(f'ALTER INDEX {schema_prefix}"RULES_STUCKSTATE_IDX" RENAME TO "RULES_STATE_IDX"')
    elif is_current_dialect('mysql'):
        execute(f'ALTER TABLE {schema_prefix}rules RENAME INDEX RULES_STUCKSTATE_IDX TO RULES_STATE_IDX')
    elif is_current_dialect('sqlite'):
        create_index('RULES_STATE_IDX', 'rules', ['state'])
        drop_index('RULES_STUCKSTATE_IDX', 'rules')


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""
    if is_current_dialect('oracle', 'postgresql'):
        execute(f'ALTER INDEX {schema_prefix}"RULES_STATE_IDX" RENAME TO "RULES_STUCKSTATE_IDX"')
    elif is_current_dialect('mysql'):
        execute(f'ALTER TABLE {schema_prefix}rules RENAME INDEX RULES_STATE_IDX TO RULES_STUCKSTATE_IDX')
    elif is_current_dialect('sqlite'):
        create_index('RULES_STUCKSTATE_IDX', 'rules', ['state'])
        drop_index('RULES_STATE_IDX', 'rules')
