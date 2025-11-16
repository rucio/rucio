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

""" added staging_area column """

import sqlalchemy as sa
from alembic.op import create_check_constraint, drop_column, drop_constraint, execute

from rucio.db.sqla.migrate_repo import add_column, get_effective_schema, is_current_dialect, qualify_table
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '3152492b110b'
down_revision = '22cf51430c78'


def upgrade():
    """
    Upgrade the database to this revision
    """

    requests_table = qualify_table('requests')

    if is_current_dialect('oracle'):
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False))
        try_drop_constraint('REQUESTS_TYPE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif is_current_dialect('postgresql'):
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False))
        drop_constraint('REQUESTS_TYPE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif is_current_dialect('mysql'):
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False))
        execute(
            f"""
            ALTER TABLE {requests_table}
            DROP CHECK REQUESTS_TYPE_CHK
            """
        )
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    schema = get_effective_schema()
    requests_table = qualify_table('requests')

    if is_current_dialect('oracle'):
        try_drop_constraint('RSE_STAGING_AREA_CHK', 'rses')
        try_drop_constraint('REQUESTS_TYPE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema)

    elif is_current_dialect('postgresql'):
        execute(
            f"""
            ALTER TABLE {requests_table}
            DROP CONSTRAINT IF EXISTS "REQUESTS_TYPE_CHK",
            ALTER COLUMN request_type TYPE CHAR
            """
        )
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema)

    elif is_current_dialect('mysql'):
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema)
