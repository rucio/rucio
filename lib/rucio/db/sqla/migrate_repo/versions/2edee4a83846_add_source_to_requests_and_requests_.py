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

''' add source to requests and requests_history '''

import sqlalchemy as sa
from alembic import context
from alembic.op import add_column, drop_column

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '2edee4a83846'
down_revision = '2f648fc909f3'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('source_rse_id', GUID()), schema=schema)
        add_column('requests_history', sa.Column('source_rse_id', GUID()), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'source_rse_id', schema=schema)
        drop_column('requests_history', 'source_rse_id', schema=schema)
