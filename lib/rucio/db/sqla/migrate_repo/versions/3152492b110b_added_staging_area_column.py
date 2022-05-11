# -*- coding: utf-8 -*-
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
from alembic import context, op
from alembic.op import add_column, create_check_constraint, drop_constraint, drop_column

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '3152492b110b'
down_revision = '22cf51430c78'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False))
        try_drop_constraint('REQUESTS_TYPE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif context.get_context().dialect.name == 'postgresql':
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False), schema=schema[:-1])
        drop_constraint('REQUESTS_TYPE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif context.get_context().dialect.name == 'mysql':
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True), default=False), schema=schema[:-1])
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('RSE_STAGING_AREA_CHK', 'rses')
        try_drop_constraint('REQUESTS_TYPE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area')

    elif context.get_context().dialect.name == 'postgresql':
        op.execute('ALTER TABLE ' + schema + 'requests DROP CONSTRAINT IF EXISTS "REQUESTS_TYPE_CHK", ALTER COLUMN request_type TYPE CHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema[:-1])
