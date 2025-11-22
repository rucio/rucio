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

""" add mismatch scheme state to requests """

from alembic.op import execute

from rucio.db.sqla.migrate_repo import (
    create_check_constraint,
    is_current_dialect,
    qualify_table,
    try_drop_constraint,
)

# Alembic revision identifiers
revision = '21d6b9dc9961'
down_revision = '5f139f77382a'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'postgresql'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M')")

    elif is_current_dialect('mysql'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M')")


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    requests_table = qualify_table('requests')

    if is_current_dialect('oracle'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")

    elif is_current_dialect('postgresql'):
        execute(
            f"""
            ALTER TABLE {requests_table}
            DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK",
            ALTER COLUMN state TYPE CHAR
            """
        )
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")

    elif is_current_dialect('mysql'):
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")
