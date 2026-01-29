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

"""Introduce request cancellation"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context, op
from alembic.op import create_check_constraint, create_index, create_primary_key, create_table, drop_table
from sqlalchemy.exc import DatabaseError

from rucio.db.sqla.types import GUID
from rucio.db.sqla.util import try_drop_constraint


def _mysql_drop_check_constraint_if_exists(schema: str, table: str, constraint: str) -> None:
    """Drop a check constraint if it exists on MySQL 8+."""
    try:
        op.execute('ALTER TABLE %s%s DROP CHECK %s' % (schema, table, constraint))
    except DatabaseError as e:
        if e.orig.args[0] != 3821:  # Check constraint not found
            raise

# Alembic revision identifiers
revision = '3f2b52303b26'
down_revision = '3b943000da18'


def enum_values_str(enumvals):
    return ', '.join(map(lambda x: x.join(("'", "'")), enumvals))

def upgrade():
    """Upgrade the database to this revision."""
    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    dialect = context.get_context().dialect.name

    new_enum_values = ['Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M', 'P', 'X', 'C']

    if dialect in ['oracle', 'mysql', 'postgresql']:
        # Create updated_requests table
        create_table(
            'updated_requests',
            sa.Column('id', GUID()),
            sa.Column('request_id', GUID()),
            sa.Column('state', sa.Enum(*new_enum_values, name='UPDATED_REQUESTS_STATE_CHK', create_constraint=True)),
            sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
            sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
        )

        create_primary_key('UPDATED_REQUESTS_PK', 'updated_requests', ['id'])
        create_check_constraint('UPDATED_REQUESTS_REQUEST_ID_NN', 'updated_requests', 'request_id is not null')
        create_index('UPDATED_REQUESTS_REQUEST_ID_IDX', 'updated_requests', ['request_id'])

    # Update state check constraints to include CANCELLING and CANCELLED
    if dialect == 'oracle':
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(new_enum_values)})',
        )
        try_drop_constraint('REQUESTS_HIST_STATE_CHK', 'requests_history')
        op.create_check_constraint(
            constraint_name='REQUESTS_HIST_STATE_CHK',
            table_name='requests_history',
            condition=f'state in ({enum_values_str(new_enum_values)})',
        )
    elif dialect == 'postgresql':
        # Recreate enum types with new values (handles bug in previous migration where type may not exist)
        op.execute('ALTER TABLE %srequests_history DROP CONSTRAINT IF EXISTS "REQUESTS_HISTORY_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema)
        op.execute('DROP TYPE IF EXISTS "REQUESTS_HISTORY_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_HISTORY_STATE_CHK" AS ENUM({enum_values_str(new_enum_values)})')
        op.execute('ALTER TABLE %srequests_history ALTER COLUMN state TYPE "REQUESTS_HISTORY_STATE_CHK" USING state::"REQUESTS_HISTORY_STATE_CHK"' % schema)
        op.execute('ALTER TABLE %srequests DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema)
        op.execute('DROP TYPE IF EXISTS "REQUESTS_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_STATE_CHK" AS ENUM({enum_values_str(new_enum_values)})')
        op.execute('ALTER TABLE %srequests ALTER COLUMN state TYPE "REQUESTS_STATE_CHK" USING state::"REQUESTS_STATE_CHK"' % schema)
    elif dialect == 'mysql':
        if context.get_context().dialect.server_version_info[0] >= 8:
            _mysql_drop_check_constraint_if_exists(schema, 'requests', 'REQUESTS_STATE_CHK')
            _mysql_drop_check_constraint_if_exists(schema, 'requests_history', 'REQUESTS_HIST_STATE_CHK')
        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(new_enum_values)})',
        )
        op.create_check_constraint(
            constraint_name='REQUESTS_HIST_STATE_CHK',
            table_name='requests_history',
            condition=f'state in ({enum_values_str(new_enum_values)})',
        )


def downgrade():
    """Downgrade the database to the previous revision."""
    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    dialect = context.get_context().dialect.name

    old_enum_values = ['Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M', 'P']

    if dialect in ['oracle', 'mysql', 'postgresql']:
        drop_table('updated_requests')
        if dialect == 'postgresql':
            op.execute('DROP TYPE IF EXISTS "UPDATED_REQUESTS_STATE_CHK"')

    # Migrate requests in CANCELLING ('X') or CANCELLED ('C') states to FAILED ('F')
    op.execute("UPDATE %srequests SET state = 'F', err_msg = 'Cancelled by DB downgrade' WHERE state IN ('X', 'C')" % schema)
    op.execute("UPDATE %srequests_history SET state = 'F', err_msg = 'Cancelled by DB downgrade' WHERE state IN ('X', 'C')" % schema)

    # Revert state check constraints
    if dialect == 'oracle':
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        op.create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(old_enum_values)})',
        )
        try_drop_constraint('REQUESTS_HIST_STATE_CHK', 'requests_history')
        op.create_check_constraint(
            constraint_name='REQUESTS_HIST_STATE_CHK',
            table_name='requests_history',
            condition=f'state in ({enum_values_str(old_enum_values)})',
        )
    elif dialect == 'postgresql':
        # Recreate enum types without X and C values
        op.execute('ALTER TABLE %srequests_history DROP CONSTRAINT IF EXISTS "REQUESTS_HISTORY_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema)
        op.execute('DROP TYPE IF EXISTS "REQUESTS_HISTORY_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_HISTORY_STATE_CHK" AS ENUM({enum_values_str(old_enum_values)})')
        op.execute('ALTER TABLE %srequests_history ALTER COLUMN state TYPE "REQUESTS_HISTORY_STATE_CHK" USING state::"REQUESTS_HISTORY_STATE_CHK"' % schema)
        op.execute('ALTER TABLE %srequests DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK", ALTER COLUMN state TYPE CHAR' % schema)
        op.execute('DROP TYPE IF EXISTS "REQUESTS_STATE_CHK"')
        op.execute(f'CREATE TYPE "REQUESTS_STATE_CHK" AS ENUM({enum_values_str(old_enum_values)})')
        op.execute('ALTER TABLE %srequests ALTER COLUMN state TYPE "REQUESTS_STATE_CHK" USING state::"REQUESTS_STATE_CHK"' % schema)
    elif dialect == 'mysql':
        if context.get_context().dialect.server_version_info[0] >= 8:
            _mysql_drop_check_constraint_if_exists(schema, 'requests', 'REQUESTS_STATE_CHK')
            _mysql_drop_check_constraint_if_exists(schema, 'requests_history', 'REQUESTS_HIST_STATE_CHK')
        else:
            op.create_check_constraint(
                constraint_name='REQUESTS_STATE_CHK',
                table_name='requests',
                condition=f'state in ({enum_values_str(old_enum_values)})',
            )
            op.create_check_constraint(
                constraint_name='REQUESTS_HIST_STATE_CHK',
                table_name='requests_history',
                condition=f'state in ({enum_values_str(old_enum_values)})',
            )
