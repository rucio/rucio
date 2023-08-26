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

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('bytes', sa.BigInteger), schema=schema)
        add_column('requests', sa.Column('md5', String(32)), schema=schema)
        add_column('requests', sa.Column('adler32', String(8)), schema=schema)
        add_column('requests', sa.Column('dest_url', String(2048)), schema=schema)
        add_column('requests_history', sa.Column('bytes', sa.BigInteger), schema=schema)
        add_column('requests_history', sa.Column('md5', String(32)), schema=schema)
        add_column('requests_history', sa.Column('adler32', String(8)), schema=schema)
        add_column('requests_history', sa.Column('dest_url', String(2048)), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'bytes', schema=schema)
        drop_column('requests', 'md5', schema=schema)
        drop_column('requests', 'adler32', schema=schema)
        drop_column('requests', 'dest_url', schema=schema)
        drop_column('requests_history', 'bytes', schema=schema)
        drop_column('requests_history', 'md5', schema=schema)
        drop_column('requests_history', 'adler32', schema=schema)
        drop_column('requests_history', 'dest_url', schema=schema)
