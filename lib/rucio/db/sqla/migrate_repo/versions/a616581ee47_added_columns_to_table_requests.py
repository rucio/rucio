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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' added columns to table requests '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

from rucio.db.sqla.models import String


# Alembic revision identifiers
revision = 'a616581ee47'
down_revision = '2854cd9e168'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        add_column('requests', sa.Column('bytes', sa.BigInteger))
        add_column('requests', sa.Column('md5', String(32)))
        add_column('requests', sa.Column('adler32', String(8)))
        add_column('requests', sa.Column('dest_url', String(2048)))
        add_column('requests_history', sa.Column('bytes', sa.BigInteger))
        add_column('requests_history', sa.Column('md5', String(32)))
        add_column('requests_history', sa.Column('adler32', String(8)))
        add_column('requests_history', sa.Column('dest_url', String(2048)))

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        drop_column('requests', 'bytes')
        drop_column('requests', 'md5')
        drop_column('requests', 'adler32')
        drop_column('requests', 'dest_url')
        drop_column('requests_history', 'bytes')
        drop_column('requests_history', 'md5')
        drop_column('requests_history', 'adler32')
        drop_column('requests_history', 'dest_url')

    elif context.get_context().dialect.name == 'postgresql':
        pass
