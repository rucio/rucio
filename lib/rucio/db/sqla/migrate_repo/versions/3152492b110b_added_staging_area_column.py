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

''' added staging_area column '''

import sqlalchemy as sa
from alembic import op
from alembic.op import add_column, create_check_constraint, drop_column, drop_constraint

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '3152492b110b'
down_revision = '22cf51430c78'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle'):
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False), schema=schema)
        try_drop_constraint('REQUESTS_TYPE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif is_current_dialect('postgresql'):
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False), schema=schema)
        drop_constraint('REQUESTS_TYPE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif is_current_dialect('mysql'):
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False), schema=schema)
        op.execute('ALTER TABLE ' + schema_prefix + 'requests DROP CHECK REQUESTS_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle'):
        try_drop_constraint('RSE_STAGING_AREA_CHK', 'rses')
        try_drop_constraint('REQUESTS_TYPE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema)

    elif is_current_dialect('postgresql'):
        op.execute('ALTER TABLE ' + schema_prefix + 'requests DROP CONSTRAINT IF EXISTS "REQUESTS_TYPE_CHK", ALTER COLUMN request_type TYPE CHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema)

    elif is_current_dialect('mysql'):
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema)
