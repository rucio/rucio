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

"""
Add PREPARING state to Request model.
"""

from alembic import op

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = 'd23453595260'
down_revision = '8ea9122275b1'


def upgrade():
    """
    Upgrade the database to this revision
    """

    new_enum_values = ['Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M', 'P']

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""
    if is_current_dialect('oracle'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(new_enum_values)})',
            schema=schema,
        )
    elif is_current_dialect('postgresql'):
        op.execute('ALTER TABLE %srequests_history DROP CONSTRAINT IF EXISTS "REQUESTS_HISTORY_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema_prefix)
        op.execute('DROP TYPE "REQUESTS_HISTORY_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_HISTORY_STATE_CHK" AS ENUM({enum_values_str(new_enum_values)})')
        op.execute('ALTER TABLE %srequests_history ALTER COLUMN state TYPE "REQUESTS_HISTORY_STATE_CHK" USING state::"REQUESTS_HISTORY_STATE_CHK"' % schema_prefix)
        op.execute('ALTER TABLE %srequests DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema_prefix)
        op.execute('DROP TYPE "REQUESTS_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_STATE_CHK" AS ENUM({enum_values_str(new_enum_values)})')
        op.execute('ALTER TABLE %srequests ALTER COLUMN state TYPE "REQUESTS_STATE_CHK" USING state::"REQUESTS_STATE_CHK"' % schema_prefix)

    elif is_current_dialect('mysql'):
        if op.get_context().dialect.server_version_info[0] == 8:
            op.drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check', schema=schema)

        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(new_enum_values)})',
            schema=schema,
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    old_enum_values = ['Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M']

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(old_enum_values)})',
            schema=schema,
        )
    elif is_current_dialect('postgresql'):
        op.execute('ALTER TABLE %srequests_history DROP CONSTRAINT IF EXISTS "REQUESTS_HISTORY_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema_prefix)
        op.execute(f'CREATE TYPE "REQUESTS_HISTORY_STATE_CHK" AS ENUM({enum_values_str(old_enum_values)})')
        op.execute('ALTER TABLE %srequests_history ALTER COLUMN state TYPE "REQUESTS_HISTORY_STATE_CHK" USING state::"REQUESTS_HISTORY_STATE_CHK"' % schema_prefix)
        op.execute('ALTER TABLE %srequests DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema_prefix)
        op.execute('DROP TYPE "REQUESTS_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_STATE_CHK" AS ENUM({enum_values_str(old_enum_values)})')
        op.execute('ALTER TABLE %srequests ALTER COLUMN state TYPE "REQUESTS_STATE_CHK" USING state::"REQUESTS_STATE_CHK"' % schema_prefix)

    elif is_current_dialect('mysql'):
        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(old_enum_values)})',
            schema=schema,
        )

        if op.get_context().dialect.server_version_info[0] == 8:
            op.drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check', schema=schema)


def enum_values_str(enumvals):
    return ', '.join(map(lambda x: x.join(("'", "'")), enumvals))
