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

''' switch heartbeats executable '''

import sqlalchemy as sa

from alembic import context
from alembic.op import create_primary_key, add_column, drop_constraint, drop_column

from rucio.db.sqla.models import String


# Alembic revision identifiers
revision = '277b5fbb41d3'
down_revision = '44278720f774'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        drop_constraint('heartbeats_pk', 'heartbeats', type_='primary')
        drop_column('heartbeats', 'executable')
        add_column('heartbeats', sa.Column('executable', String(64)))
        add_column('heartbeats', sa.Column('readable', String(4000)))
        create_primary_key('HEARTBEATS_PK', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        drop_constraint('heartbeats_pk', 'heartbeats', type_='primary')
        drop_column('heartbeats', 'executable')
        drop_column('heartbeats', 'readable')
        add_column('heartbeats', sa.Column('executable', String(767)))
        create_primary_key('HEARTBEATS_PK', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])

    elif context.get_context().dialect.name == 'postgresql':
        pass
