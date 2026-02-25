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
revision = '7ec22226cdbf'
down_revision = '3345511706b8'


def upgrade():
    """
    Upgrade the database to this revision
    """

    replicas_table = qualify_table('replicas')
    replicas_state_values = ['A', 'U', 'C', 'B', 'D', 'S', 'T']

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )

    elif is_current_dialect('postgresql'):
        replicas_state_enum = render_enum_name('REPLICAS_STATE_CHK')

        # 1) Old CHECK is no longer needed once we rely on the enum.
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')

        # 2) Ensure the enum exists for CHAR+CHECK-only databases.
        try_create_enum_if_absent('REPLICAS_STATE_CHK', replicas_state_values)

        # 3) Add the new 'T' state if it isn't present yet.
        try_alter_enum_add_value(
            'REPLICAS_STATE_CHK',
            'T',
            after='S',
            if_not_exists=True,
        )

        # 4) Attach/re-attach the enum type to the column.
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE {replicas_state_enum}
            USING state::text::{replicas_state_enum}
            """
        )

    elif is_current_dialect('mysql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    replicas_table = qualify_table('replicas')
    replicas_state_values = ['A', 'U', 'C', 'B', 'D', 'S']

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )

    elif is_current_dialect('postgresql'):
        replicas_state_enum = render_enum_name('REPLICAS_STATE_CHK')
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REPLICAS_STATE_CHK')
        try_create_enum_if_absent('REPLICAS_STATE_CHK', replicas_state_values)
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE {replicas_state_enum}
            USING state::{replicas_state_enum}
            """
        )

    elif is_current_dialect('mysql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )
