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

''' added source history table '''

import sqlalchemy as sa

from alembic.op import create_table, add_column, drop_column, drop_table
from alembic import context

from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '575767d9f89'
down_revision = '379a19b5332d'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('sources_history',
                     sa.Column('request_id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('dest_rse_id', GUID()),
                     sa.Column('url', sa.String(2048)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('ranking', sa.Integer()),
                     sa.Column('is_using', sa.Boolean(), default=False))
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('estimated_at', sa.DateTime), schema=schema)
        add_column('requests_history', sa.Column('estimated_at', sa.DateTime), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'estimated_at', schema=schema)
        drop_column('requests_history', 'estimated_at', schema=schema)
        drop_table('sources_history')
