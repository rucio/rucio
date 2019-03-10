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
# - Martin Barisits <martin.barisits@cern.ch>, 2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' added comment column to rules '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

from rucio.db.sqla.models import String


# Alembic revision identifiers
revision = 'ae2a56fcc89'
down_revision = '45378a1e76a8'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema
        add_column('rules', sa.Column('comments', String(255)), schema=schema)
        add_column('rules_hist_recent', sa.Column('comments', String(255)), schema=schema)
        add_column('rules_history', sa.Column('comments', String(255)), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema
        drop_column('rules', 'comments', schema=schema)
        drop_column('rules_hist_recent', 'comments', schema=schema)
        drop_column('rules_history', 'comments', schema=schema)
