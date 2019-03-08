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
# - Joaquin Bogado <jbogadog@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017

''' add estimator columns to request table '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column


# Alembic revision identifiers
revision = '94a5961ddbf2'
down_revision = '1c45d9730ca6'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        add_column('requests', sa.Column('estimated_started_at', sa.DateTime()))
        add_column('requests', sa.Column('estimated_transferred_at', sa.DateTime()))

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        drop_column('requests', 'estimated_started_at')
        drop_column('requests', 'estimated_transferred_at')

    elif context.get_context().dialect.name == 'postgresql':
        pass
