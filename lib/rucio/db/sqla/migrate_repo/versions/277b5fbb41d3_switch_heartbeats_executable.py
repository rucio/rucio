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

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('heartbeats_pk', 'heartbeats', type_='primary')
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('heartbeats', 'executable', schema=schema)
        add_column('heartbeats', sa.Column('executable', String(64)), schema=schema)
        add_column('heartbeats', sa.Column('readable', String(4000)), schema=schema)
        create_primary_key('HEARTBEATS_PK', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('heartbeats_pk', 'heartbeats', type_='primary')
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('heartbeats', 'executable', schema=schema)
        drop_column('heartbeats', 'readable', schema=schema)
        add_column('heartbeats', sa.Column('executable', String(767)), schema=schema)
        create_primary_key('HEARTBEATS_PK', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])
