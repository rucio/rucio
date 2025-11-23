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

""" Removal of ReplicaState.SOURCE """

from alembic.op import execute

from rucio.db.sqla.migrate_repo import (
    create_check_constraint,
    enum_values_clause,
    is_current_dialect,
    qualify_table,
    render_enum_name,
    try_drop_constraint,
    try_drop_enum,
)

# Alembic revision identifiers
revision = 'b7d287de34fd'
down_revision = 'f1b14a8c2ac1'


def upgrade():
    """
    Upgrade the database to this revision
    """

    collection_replicas_table = qualify_table('collection_replicas')
    replicas_table = qualify_table('replicas')
    replicas_state_values = ['A', 'U', 'C', 'B', 'D', 'T']

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )
        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        create_check_constraint(
            constraint_name='COLLECTION_REPLICAS_STATE_CHK',
            table_name='collection_replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )

    elif is_current_dialect('postgresql'):
        replicas_state_enum = render_enum_name('REPLICAS_STATE_CHK')
        collection_replicas_state_enum = render_enum_name('COLLECTION_REPLICAS_STATE_CHK')
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REPLICAS_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {replicas_state_enum} AS ENUM({enum_values_clause(replicas_state_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE {replicas_state_enum}
            USING state::{replicas_state_enum}
            """
        )

        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        execute(
            f"""
            ALTER TABLE {collection_replicas_table}
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('COLLECTION_REPLICAS_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {collection_replicas_state_enum} AS ENUM({enum_values_clause(replicas_state_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {collection_replicas_table}
            ALTER COLUMN state TYPE {collection_replicas_state_enum}
            USING state::{collection_replicas_state_enum}
            """
        )

    elif is_current_dialect('mysql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )
        create_check_constraint(
            constraint_name='COLLECTION_REPLICAS_STATE_CHK',
            table_name='collection_replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    collection_replicas_table = qualify_table('collection_replicas')
    replicas_table = qualify_table('replicas')
    replicas_state_values = ['A', 'U', 'C', 'B', 'D', 'S', 'T']

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )
        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        create_check_constraint(
            constraint_name='COLLECTION_REPLICAS_STATE_CHK',
            table_name='collection_replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )

    elif is_current_dialect('postgresql'):
        replicas_state_enum = render_enum_name('REPLICAS_STATE_CHK')
        collection_replicas_state_enum = render_enum_name('COLLECTION_REPLICAS_STATE_CHK')
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('REPLICAS_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {replicas_state_enum} AS ENUM({enum_values_clause(replicas_state_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {replicas_table}
            ALTER COLUMN state TYPE {replicas_state_enum}
            USING state::{replicas_state_enum}
            """
        )

        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        execute(
            f"""
            ALTER TABLE {collection_replicas_table}
            ALTER COLUMN state TYPE CHAR
            """
        )
        try_drop_enum('COLLECTION_REPLICAS_STATE_CHK')
        execute(
            f"""
            CREATE TYPE {collection_replicas_state_enum} AS ENUM({enum_values_clause(replicas_state_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {collection_replicas_table}
            ALTER COLUMN state TYPE {collection_replicas_state_enum}
            USING state::{collection_replicas_state_enum}
            """
        )

    elif is_current_dialect('mysql'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(
            constraint_name='REPLICAS_STATE_CHK',
            table_name='replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )
        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        create_check_constraint(
            constraint_name='COLLECTION_REPLICAS_STATE_CHK',
            table_name='collection_replicas',
            condition=f"state in ({enum_values_clause(replicas_state_values)})",
        )
