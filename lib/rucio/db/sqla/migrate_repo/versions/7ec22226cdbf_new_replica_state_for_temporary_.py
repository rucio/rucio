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

""" new replica state for temporary unavailable replicas """

from alembic.op import execute

from rucio.db.sqla.migrate_repo import (
    create_check_constraint,
    is_current_dialect,
    qualify_table,
    try_drop_constraint,
)

# Alembic revision identifiers
revision = '7ec22226cdbf'
down_revision = '3345511706b8'


def upgrade():
    """
    Upgrade the database to this revision
    """

    replicas_table = qualify_table('replicas')

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")

    elif is_current_dialect('postgresql'):
        execute(
            f"""
            ALTER TABLE {replicas_table}
            DROP CONSTRAINT IF EXISTS "REPLICAS_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        execute(
            """
            DROP TYPE "REPLICAS_STATE_CHK"
            """
        )
        execute(
            """
            CREATE TYPE "REPLICAS_STATE_CHK" AS ENUM('A', 'U', 'C', 'B', 'D', 'S', 'T')
            """
        )
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE "REPLICAS_STATE_CHK"
            USING state::"REPLICAS_STATE_CHK"
            """
        )

    elif is_current_dialect('mysql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    replicas_table = qualify_table('replicas')

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S')")

    elif is_current_dialect('postgresql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE CHAR
            """
        )
        execute(
            """
            DROP TYPE "REPLICAS_STATE_CHK"
            """
        )
        execute(
            """
            CREATE TYPE "REPLICAS_STATE_CHK" AS ENUM('A', 'U', 'C', 'B', 'D', 'S')
            """
        )
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE "REPLICAS_STATE_CHK"
            USING state::"REPLICAS_STATE_CHK"
            """
        )

    elif is_current_dialect('mysql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S')")
