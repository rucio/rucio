# Copyright 2015-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Robert Illingworth <illingwo@fnal.gov>, 2019

''' added staging_area column '''

import sqlalchemy as sa

from alembic import context, op
from alembic.op import add_column, create_check_constraint, drop_constraint, drop_column


# Alembic revision identifiers
revision = '3152492b110b'
down_revision = '22cf51430c78'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK'), default=False))
        drop_constraint('REQUESTS_TYPE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif context.get_context().dialect.name == 'postgresql':
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK'), default=False), schema=schema[:-1])
        drop_constraint('REQUESTS_TYPE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK'), default=False), schema=schema[:-1])
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        add_column('rses', sa.Column('staging_area', sa.Boolean(name='RSE_STAGING_AREA_CHK'), default=False), schema=schema[:-1])
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T', 'I', '0')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        drop_constraint('RSE_STAGING_AREA_CHK', 'rses', type_='check')
        drop_constraint('REQUESTS_TYPE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area')

    elif context.get_context().dialect.name == 'postgresql':
        op.execute('ALTER TABLE ' + schema + 'requests DROP CONSTRAINT IF EXISTS "REQUESTS_TYPE_CHK", ALTER COLUMN request_type TYPE CHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_TYPE_CHK', table_name='requests',
                                condition="request_type in ('U', 'D', 'T')")
        drop_column('rses', 'staging_area', schema=schema[:-1])
