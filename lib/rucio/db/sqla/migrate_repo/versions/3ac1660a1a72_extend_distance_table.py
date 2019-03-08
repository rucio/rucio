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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' extend distance table '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column


# Alembic revision identifiers
revision = '3ac1660a1a72'
down_revision = '5673b4b6e843'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        add_column('distances', sa.Column('packet_loss', sa.Integer))
        add_column('distances', sa.Column('latency', sa.Integer))
        add_column('distances', sa.Column('mbps_file', sa.Integer))
        add_column('distances', sa.Column('mbps_link', sa.Integer))
        add_column('distances', sa.Column('queued_total', sa.Integer))
        add_column('distances', sa.Column('done_1h', sa.Integer))
        add_column('distances', sa.Column('done_6h', sa.Integer))

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        drop_column('distances', 'packet_loss')
        drop_column('distances', 'latency')
        drop_column('distances', 'mbps_file')
        drop_column('distances', 'mbps_link')
        drop_column('distances', 'queued_total')
        drop_column('distances', 'done_1h')
        drop_column('distances', 'done_6h')

    elif context.get_context().dialect.name == 'postgresql':
        pass
