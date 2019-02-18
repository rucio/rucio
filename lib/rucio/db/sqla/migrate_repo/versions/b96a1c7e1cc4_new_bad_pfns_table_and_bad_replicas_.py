# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# New bad_pfns table and bad_replicas changes
#
# Revision ID: b96a1c7e1cc4
# Revises: 1f46c5f240ac
# Create Date: 2018-11-30 09:12:47.237455

from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, create_table, create_foreign_key,
                        add_column, create_index, drop_table, drop_column,
                        drop_index)

from alembic import (context, op)

import sqlalchemy as sa

from rucio.db.sqla.constants import BadPFNStatus

# revision identifiers, used by Alembic.
revision = 'b96a1c7e1cc4'  # pylint: disable=invalid-name
down_revision = '1f46c5f240ac'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    # Create new bad_pfns table
    create_table('bad_pfns',
                 sa.Column('path', sa.String(2048)),
                 sa.Column('state', BadPFNStatus.db_type(name='BAD_PFNS_STATE_CHK'), default=BadPFNStatus.SUSPICIOUS),
                 sa.Column('reason', sa.String(255)),
                 sa.Column('account', sa.String(25)),
                 sa.Column('expires_at', sa.DateTime),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('BAD_PFNS_PK', 'bad_pfns', ['path', 'state'])
        create_foreign_key('BAD_PFNS_ACCOUNT_FK', 'bad_pfns', 'accounts', ['account'], ['account'])

    # Add new state to bad_replicas table
    if context.get_context().dialect.name != 'sqlite':
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be renamed first
            op.execute("ALTER TYPE 'BAD_REPLICAS_STATE_CHK' RENAME TO 'BAD_REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member
        else:
            drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas', type_='check')
        create_check_constraint(name='BAD_REPLICAS_STATE_CHK', source='bad_replicas', condition="state in ('B', 'D', 'L', 'R', 'S', 'T')")
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be changed to the new one and the old one needs to be dropped
            op.execute("ALTER TABLE bad_replicas ALTER COLUMN state TYPE 'BAD_REPLICAS_STATE_CHK'")  # pylint: disable=no-member
            op.execute("DROP TYPE 'BAD_REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member

    # Add new column to bad_replicas table
    add_column('bad_replicas', sa.Column('expires_at', sa.DateTime()))

    # Change PK
    drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
    create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'state', 'created_at'])

    # Add new Index to Table
    create_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas', ['expires_at'])


def downgrade():
    '''
    downgrade method
    '''
    drop_table('bad_pfns')

    drop_index('BAD_REPLICAS_EXPIRES_AT_IDX', 'bad_replicas')

    if context.get_context().dialect.name != 'sqlite':
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be renamed first
            op.execute("ALTER TYPE 'BAD_REPLICAS_STATE_CHK' RENAME TO 'BAD_REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member
        else:
            drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas', type_='check')
        create_check_constraint(name='BAD_REPLICAS_STATE_CHK', source='bad_replicas', condition="state in ('B', 'D', 'L', 'R', 'S')")
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be changed to the new one and the old one needs to be dropped
            op.execute("ALTER TABLE bad_replicas ALTER COLUMN state TYPE 'BAD_REPLICAS_STATE_CHK'")  # pylint: disable=no-member
            op.execute("DROP TYPE 'BAD_REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member
        drop_column('bad_replicas', 'expires_at')
        drop_constraint('BAD_REPLICAS_STATE_PK', 'bad_replicas', type_='primary')
        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'created_at'])
