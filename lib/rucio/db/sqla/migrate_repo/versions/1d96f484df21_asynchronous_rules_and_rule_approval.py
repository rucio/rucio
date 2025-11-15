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

''' asynchronous rules and rule approval '''

import sqlalchemy as sa
from alembic.op import add_column, create_check_constraint, drop_column, execute

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect, qualify_table
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '1d96f484df21'
down_revision = '3d9813fab443'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = get_effective_schema()
    rules_table = qualify_table('rules')

    if is_current_dialect('oracle'):
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True), default=False), schema=schema)
        try_drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O', 'W', 'I')")

    elif is_current_dialect('postgresql'):
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True), default=False), schema=schema)
        execute(
            f"""
            ALTER TABLE {rules_table}
            DROP CONSTRAINT IF EXISTS "RULES_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        execute("DROP TYPE \"RULES_STATE_CHK\"")
        execute("CREATE TYPE \"RULES_STATE_CHK\" AS ENUM('S', 'R', 'U', 'O', 'W', 'I')")
        execute(
            f"""
            ALTER TABLE {rules_table}
            ALTER COLUMN state TYPE "RULES_STATE_CHK"
            USING state::"RULES_STATE_CHK"
            """
        )

    elif is_current_dialect('mysql'):
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True), default=False), schema=schema)
        execute(
            f"""
            ALTER TABLE {rules_table}
            DROP CHECK RULES_STATE_CHK
            """
        )
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O', 'W', 'I')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = get_effective_schema()
    rules_table = qualify_table('rules')

    if is_current_dialect('oracle'):
        drop_column('rules', 'ignore_account_limit', schema=schema)
        try_drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O')")

    elif is_current_dialect('postgresql'):
        drop_column('rules', 'ignore_account_limit', schema=schema)
        execute(
            f"""
            ALTER TABLE {rules_table}
            DROP CONSTRAINT IF EXISTS "RULES_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        execute("DROP TYPE \"RULES_STATE_CHK\"")
        execute("CREATE TYPE \"RULES_STATE_CHK\" AS ENUM('S', 'R', 'U', 'O')")
        execute(
            f"""
            ALTER TABLE {rules_table}
            ALTER COLUMN state TYPE "RULES_STATE_CHK"
            USING state::"RULES_STATE_CHK"
            """
        )

    elif is_current_dialect('mysql'):
        drop_column('rules', 'ignore_account_limit', schema=schema)
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O')")
