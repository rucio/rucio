# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019-2020
# - Robert Illingworth <illingwo@fnal.gov>, 2019

''' new bad_pfns table and bad_replicas changes '''

import datetime

import sqlalchemy as sa

from alembic import context, op
from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, create_table, create_foreign_key,
                        add_column, create_index, drop_table, drop_column,
                        drop_index)

from rucio.db.sqla.constants import BadPFNStatus


# Alembic revision identifiers
revision = 'b96a1c7e1cc4'
down_revision = '1f46c5f240ac'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        # Create new bad_pfns table
        create_table('bad_pfns',
                     sa.Column('path', sa.String(2048)),
                     sa.Column('state', sa.Enum(BadPFNStatus, name='BAD_PFNS_STATE_CHK', values_callable=lambda obj: [e.value for e in obj]), default=BadPFNStatus.SUSPICIOUS),
                     sa.Column('reason', sa.String(255)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('expires_at', sa.DateTime),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('BAD_PFNS_PK', 'bad_pfns', ['path', 'state'])
        create_foreign_key('BAD_PFNS_ACCOUNT_FK', 'bad_pfns', 'accounts', ['account'], ['account'])

        drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas', type_='check')
        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S', 'T')")

        # Add new column to bad_replicas table
        add_column('bad_replicas', sa.Column('expires_at', sa.DateTime()), schema=schema[:-1])

        # Change PK
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'state', 'created_at'])

        # Add new Index to Table
        create_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas', ['expires_at'])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        # Create new bad_pfns table
        create_table('bad_pfns',
                     sa.Column('path', sa.String(2048)),
                     sa.Column('state', sa.Enum(BadPFNStatus, name='BAD_PFNS_STATE_CHK', values_callable=lambda obj: [e.value for e in obj]), default=BadPFNStatus.SUSPICIOUS),
                     sa.Column('reason', sa.String(255)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('expires_at', sa.DateTime),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('BAD_PFNS_PK', 'bad_pfns', ['path', 'state'])
        create_foreign_key('BAD_PFNS_ACCOUNT_FK', 'bad_pfns', 'accounts', ['account'], ['account'])

        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S', 'T')")

        # Add new column to bad_replicas table
        add_column('bad_replicas', sa.Column('expires_at', sa.DateTime()), schema=schema[:-1])

        # Change PK
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'state', 'created_at'])

        # Add new Index to Table
        create_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas', ['expires_at'])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        # Create new bad_pfns table
        create_table('bad_pfns',
                     sa.Column('path', sa.String(2048)),
                     sa.Column('state', sa.Enum(BadPFNStatus, name='BAD_PFNS_STATE_CHK', values_callable=lambda obj: [e.value for e in obj]), default=BadPFNStatus.SUSPICIOUS),
                     sa.Column('reason', sa.String(255)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('expires_at', sa.DateTime),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('BAD_PFNS_PK', 'bad_pfns', ['path', 'state'])
        create_foreign_key('BAD_PFNS_ACCOUNT_FK', 'bad_pfns', 'accounts', ['account'], ['account'])

        op.execute('ALTER TABLE ' + schema + 'bad_replicas DROP CHECK BAD_REPLICAS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S', 'T')")

        # Add new column to bad_replicas table
        add_column('bad_replicas', sa.Column('expires_at', sa.DateTime()), schema=schema[:-1])

        # Change PK
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'state', 'created_at'])

        # Add new Index to Table
        create_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas', ['expires_at'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        drop_table('bad_pfns')
        drop_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas')

        drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas', type_='check')
        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")

        drop_column('bad_replicas', 'expires_at')
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'created_at'])

    elif context.get_context().dialect.name == 'postgresql':
        drop_table('bad_pfns')
        drop_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas')

        op.execute('ALTER TABLE ' + schema + 'bad_replicas DROP CONSTRAINT IF EXISTS "BAD_REPLICAS_STATE_CHK", ALTER COLUMN state TYPE CHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")

        drop_column('bad_replicas', 'expires_at', schema=schema[:-1])
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'created_at'])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        drop_table('bad_pfns')
        drop_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas')

        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")

        drop_column('bad_replicas', 'expires_at', schema=schema[:-1])
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'created_at'])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        drop_table('bad_pfns')
        drop_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas')

        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")

        drop_column('bad_replicas', 'expires_at', schema=schema[:-1])
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'created_at'])
