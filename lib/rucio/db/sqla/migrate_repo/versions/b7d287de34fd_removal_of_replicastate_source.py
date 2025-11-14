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

''' Removal of ReplicaState.SOURCE '''

from alembic import op
from alembic.op import create_check_constraint

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = 'b7d287de34fd'
down_revision = 'f1b14a8c2ac1'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")
        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")

    elif is_current_dialect('postgresql'):
        op.execute('ALTER TABLE ' + schema_prefix + 'replicas DROP CONSTRAINT IF EXISTS "REPLICAS_STATE_CHK", ALTER COLUMN state TYPE CHAR')
        op.execute('DROP TYPE "REPLICAS_STATE_CHK"')
        op.execute("CREATE TYPE \"REPLICAS_STATE_CHK\" AS ENUM('A', 'U', 'C', 'B', 'D', 'T')")
        op.execute("ALTER TABLE %sreplicas ALTER COLUMN state TYPE \"REPLICAS_STATE_CHK\" USING state::\"REPLICAS_STATE_CHK\"" % schema_prefix)

        op.execute('ALTER TABLE ' + schema_prefix + 'collection_replicas DROP CONSTRAINT IF EXISTS "COLLECTION_REPLICAS_STATE_CHK", ALTER COLUMN state TYPE CHAR')
        op.execute('DROP TYPE "COLLECTION_REPLICAS_STATE_CHK"')
        op.execute("CREATE TYPE \"COLLECTION_REPLICAS_STATE_CHK\" AS ENUM('A', 'U', 'C', 'B', 'D', 'T')")
        op.execute("ALTER TABLE %scollection_replicas ALTER COLUMN state TYPE \"COLLECTION_REPLICAS_STATE_CHK\" USING state::\"COLLECTION_REPLICAS_STATE_CHK\"" % schema_prefix)

    elif is_current_dialect('mysql'):
        op.execute('ALTER TABLE ' + schema_prefix + 'replicas DROP CHECK REPLICAS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle'):
        try_drop_constraint('REPLICAS_STATE_CHK', 'replicas')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")

    elif is_current_dialect('postgresql'):
        op.execute('ALTER TABLE ' + schema_prefix + 'replicas DROP CONSTRAINT IF EXISTS "REPLICAS_STATE_CHK", ALTER COLUMN state TYPE CHAR')
        op.execute('DROP TYPE "REPLICAS_STATE_CHK"')
        op.execute("CREATE TYPE \"REPLICAS_STATE_CHK\" AS ENUM('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        op.execute("ALTER TABLE %sreplicas ALTER COLUMN state TYPE \"REPLICAS_STATE_CHK\" USING state::\"REPLICAS_STATE_CHK\"" % schema_prefix)

        op.execute('ALTER TABLE ' + schema_prefix + 'collection_replicas DROP CONSTRAINT IF EXISTS "COLLECTION_REPLICAS_STATE_CHK", ALTER COLUMN state TYPE CHAR')
        op.execute('DROP TYPE "COLLECTION_REPLICAS_STATE_CHK"')
        op.execute("CREATE TYPE \"COLLECTION_REPLICAS_STATE_CHK\" AS ENUM('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        op.execute("ALTER TABLE %scollection_replicas ALTER COLUMN state TYPE \"COLLECTION_REPLICAS_STATE_CHK\" USING state::\"COLLECTION_REPLICAS_STATE_CHK\"" % schema_prefix)

    elif is_current_dialect('mysql'):
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
