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

""" asynchronous rules and rule approval """

import sqlalchemy as sa
from alembic.op import execute

from rucio.db.sqla.migrate_repo import (
    add_column,
    create_check_constraint,
    drop_column,
    enum_values_clause,
    is_current_dialect,
    qualify_table,
    render_enum_name,
    try_alter_enum_add_value,
    try_create_enum_if_absent,
    try_drop_constraint,
    try_drop_enum,
)

# Alembic revision identifiers
revision = '1d96f484df21'
down_revision = '3d9813fab443'


def upgrade():
    """
    Upgrade the database to this revision
    """

    rules_table = qualify_table('rules')
    rules_state_values = ['S', 'R', 'U', 'O', 'W', 'I']

    if is_current_dialect('oracle'):
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True), default=False))
        try_drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint(
            'RULES_STATE_CHK',
            'rules',
            f"state IN ({enum_values_clause(rules_state_values)})",
        )

    elif is_current_dialect('postgresql'):
        rules_state_enum = render_enum_name('RULES_STATE_CHK')
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True), default=False))

        # 1) Remove legacy CHECK if still present.
        try_drop_constraint('RULES_STATE_CHK', 'rules')

        # 2) Ensure the enum exists (for CHAR+CHECK installs).
        try_create_enum_if_absent('RULES_STATE_CHK', rules_state_values)

        # 3) Extend the enum on existing enum-based installs.
        try_alter_enum_add_value(
            'RULES_STATE_CHK',
            'W',
            after='O',
            if_not_exists=True,
        )
        try_alter_enum_add_value(
            'RULES_STATE_CHK',
            'I',
            after='W',
            if_not_exists=True,
        )

        # 4) Attach/re-attach the enum type to the column.
        execute(
            f"""
            ALTER TABLE {rules_table}
            ALTER COLUMN state TYPE {rules_state_enum}
            USING state::text::{rules_state_enum}
            """
        )

    elif is_current_dialect('mysql'):
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True), default=False))
        try_drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint(
            'RULES_STATE_CHK',
            'rules',
            f"state IN ({enum_values_clause(rules_state_values)})",
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    rules_table = qualify_table('rules')
    rules_state_values = ['S', 'R', 'U', 'O']

    if is_current_dialect('oracle', 'mysql'):
        drop_column('rules', 'ignore_account_limit')
        try_drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint(
            'RULES_STATE_CHK',
            'rules',
            f"state IN ({enum_values_clause(rules_state_values)})",
        )

    elif is_current_dialect('postgresql'):
        rules_state_enum = render_enum_name('RULES_STATE_CHK')
        drop_column('rules', 'ignore_account_limit')
        execute(
            f"""
            ALTER TABLE {rules_table}
            DROP CONSTRAINT IF EXISTS "RULES_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('RULES_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {rules_state_enum} AS ENUM({enum_values_clause(rules_state_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {rules_table}
            ALTER COLUMN state TYPE {rules_state_enum}
            USING state::{rules_state_enum}
            """
        )
