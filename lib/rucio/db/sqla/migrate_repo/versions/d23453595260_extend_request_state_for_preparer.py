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

from alembic.op import execute, get_context

from rucio.db.sqla.migrate_repo import (
    create_check_constraint,
    is_current_dialect,
    qualify_table,
    render_enum_name,
    try_drop_constraint,
    try_drop_enum,
)

# Alembic revision identifiers
revision = 'd23453595260'
down_revision = '8ea9122275b1'


def upgrade():
    """
    Upgrade the database to this revision
    """

    new_enum_values = ['Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M', 'P']

    requests_history_table = qualify_table('requests_history')
    requests_table = qualify_table('requests')
    if is_current_dialect('oracle'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(new_enum_values)})',
        )
    elif is_current_dialect('postgresql'):

        requests_history_enum = render_enum_name('REQUESTS_HISTORY_STATE_CHK')
        requests_enum = render_enum_name('REQUESTS_STATE_CHK')

        execute(
            f"""
            ALTER TABLE {requests_history_table}
            DROP CONSTRAINT IF EXISTS "REQUESTS_HISTORY_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REQUESTS_HISTORY_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {requests_history_enum} AS ENUM({enum_values_str(new_enum_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {requests_history_table}
            ALTER COLUMN state TYPE {requests_history_enum}
            USING state::{requests_history_enum}
            """
        )
        execute(
            f"""
            ALTER TABLE {requests_table}
            DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REQUESTS_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {requests_enum} AS ENUM({enum_values_str(new_enum_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {requests_table}
            ALTER COLUMN state TYPE {requests_enum}
            USING state::{requests_enum}
            """
        )

    elif is_current_dialect('mysql'):
        if get_context().dialect.server_version_info[0] == 8:
            try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(new_enum_values)})',
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    old_enum_values = ['Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M']

    requests_history_table = qualify_table('requests_history')
    requests_table = qualify_table('requests')

    if is_current_dialect('oracle'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(old_enum_values)})',
        )
    elif is_current_dialect('postgresql'):

        requests_history_enum = render_enum_name('REQUESTS_HISTORY_STATE_CHK')
        requests_enum = render_enum_name('REQUESTS_STATE_CHK')

        execute(
            f"""
            ALTER TABLE {requests_history_table}
            DROP CONSTRAINT IF EXISTS "REQUESTS_HISTORY_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REQUESTS_HISTORY_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {requests_history_enum} AS ENUM({enum_values_str(old_enum_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {requests_history_table}
            ALTER COLUMN state TYPE {requests_history_enum}
            USING state::{requests_history_enum}
            """
        )
        execute(
            f"""
            ALTER TABLE {requests_table}
            DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REQUESTS_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {requests_enum} AS ENUM({enum_values_str(old_enum_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {requests_table}
            ALTER COLUMN state TYPE {requests_enum}
            USING state::{requests_enum}
            """
        )

    elif is_current_dialect('mysql'):
        if get_context().dialect.server_version_info[0] == 8:
            try_drop_constraint('REQUESTS_STATE_CHK', 'requests')

        create_check_constraint(
            constraint_name='REQUESTS_STATE_CHK',
            table_name='requests',
            condition=f'state in ({enum_values_str(old_enum_values)})',
        )


def enum_values_str(enumvals):
    return ', '.join(map(lambda x: x.join(("'", "'")), enumvals))
