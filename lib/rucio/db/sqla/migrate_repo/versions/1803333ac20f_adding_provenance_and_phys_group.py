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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' adding provenance and phys_group '''

import sqlalchemy as sa

from alembic.op import add_column, drop_column
from alembic import context


# Alembic revision identifiers
revision = '1803333ac20f'
down_revision = '4c3a4acfe006'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('dids', sa.Column('provenance', sa.String(2)), schema=schema)
        add_column('dids', sa.Column('phys_group', sa.String(25)), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('dids', 'provenance', schema=schema)
        drop_column('dids', 'phys_group', schema=schema)
