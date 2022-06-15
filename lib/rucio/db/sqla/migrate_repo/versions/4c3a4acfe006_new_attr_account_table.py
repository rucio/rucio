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

''' new attr account table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)


# Alembic revision identifiers
revision = '4c3a4acfe006'
down_revision = '25fc855625cf'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('account_attr_map',
                     sa.Column('account', sa.String(25)),
                     sa.Column('key', sa.String(255)),
                     sa.Column('value', sa.String(255)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('ACCOUNT_ATTR_MAP_PK', 'account_attr_map', ['account', 'key'])
        create_check_constraint('ACCOUNT_ATTR_MAP_CREATED_NN', 'account_attr_map', 'created_at is not null')
        create_check_constraint('ACCOUNT_ATTR_MAP_UPDATED_NN', 'account_attr_map', 'updated_at is not null')
        create_foreign_key('ACCOUNT_ATTR_MAP_ACCOUNT_FK', 'account_attr_map', 'accounts', ['account'], ['account'])
        create_index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'account_attr_map', ['key', 'value'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('account_attr_map')

    elif context.get_context().dialect.name == 'postgresql':
        # drop_constraint('ACCOUNT_ATTR_MAP_PK', 'account_attr_map', type_='primary')
        # drop_constraint('ACCOUNT_ATTR_MAP_CREATED_NN', 'account_attr_map')
        # drop_constraint('ACCOUNT_ATTR_MAP_UPDATED_NN', 'account_attr_map')
        # drop_constraint('ACCOUNT_ATTR_MAP_ACCOUNT_FK', 'account_attr_map')
        # drop_index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'account_attr_map')
        # drop_table('account_attr_map')
        pass
