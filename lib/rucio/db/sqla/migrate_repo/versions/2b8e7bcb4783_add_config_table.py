# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

''' add config table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key,
                        create_check_constraint,
                        drop_constraint, drop_table)


# Alembic revision identifiers
revision = '2b8e7bcb4783'
down_revision = 'd91002c5841'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('configs',
                     sa.Column('section', sa.String(128)),
                     sa.Column('opt', sa.String(128)),
                     sa.Column('value', sa.String(4000)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('configs_pk', 'configs', ['section', 'opt'])
        create_check_constraint('configs_created_nn', 'configs', 'created_at is not null')
        create_check_constraint('configs_updated_nn', 'configs', 'updated_at is not null')
        create_table('configs_history',
                     sa.Column('section', sa.String(128)),
                     sa.Column('opt', sa.String(128)),
                     sa.Column('value', sa.String(4000)),
                     sa.Column('created_at', sa.DateTime),
                     sa.Column('updated_at', sa.DateTime))

        create_primary_key('configs_history_pk', 'configs_history', ['section', 'opt', 'updated_at'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('configs')
        drop_table('configs_history')

    elif context.get_context().dialect.name == 'postgresql':
        drop_constraint('configs_pk', 'configs', type_='primary')
        drop_constraint('configs_created_nn', 'configs', type_='check')
        drop_constraint('configs_updated_nn', 'configs', type_='check')
        drop_table('configs')
        drop_constraint('configs_history_pk', 'configs_history', type_='check')
        drop_table('configs_history')
