# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015-2019
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017

''' added heartbeats '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key,
                        create_check_constraint, create_index,
                        drop_constraint, drop_table)


# Alembic revision identifiers
revision = 'a93e4e47bda'
down_revision = '2af3291ec4c'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('heartbeats',
                     sa.Column('executable', sa.String(512)),
                     sa.Column('hostname', sa.String(128)),
                     sa.Column('pid', sa.Integer(), autoincrement=False),
                     sa.Column('thread_id', sa.BigInteger(), autoincrement=False),
                     sa.Column('thread_name', sa.String(64)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('heartbeats_pk', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])
        create_index('HEARTBEATS_UPDATED_AT', 'heartbeats', ['updated_at'])
        create_check_constraint('heartbeats_created_nn', 'heartbeats', 'created_at is not null')
        create_check_constraint('heartbeats_updated_nn', 'heartbeats', 'updated_at is not null')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('heartbeats_pk', 'configs', type_='primary')
        drop_table('heartbeats')

    elif context.get_context().dialect.name == 'postgresql':
        # drop_constraint('heartbeats_pk', 'configs', type_='primary')
        # drop_index('heartbeats_updated_at', 'heartbeats')
        # drop_constraint('heartbeats_created_nn', 'heartbeats', type_='check')
        # drop_constraint('heartbeats_updated_nn', 'heartbeats', type_='check')
        # drop_table('heartbeats')
        pass
