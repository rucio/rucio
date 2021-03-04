# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Matt Snyder <msnyder@bnl.gov>, 2021

''' adding transfertool column and index to requests table'''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column, create_index, drop_index

# Alembic revision identifiers
revision = 'f85a2962b021'
down_revision = 'd23453595260'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('transfertool', sa.String(64)), schema=schema)
        add_column('requests_history', sa.Column('transfertool', sa.String(64)), schema=schema)
        create_index('REQUESTS_TYP_STA_TRA_ACT_IDX', 'requests', ['request_type', 'state', 'transfertool', 'activity'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_index('REQUESTS_TYP_STA_TRA_ACT_IDX', 'requests')
        drop_column('requests', 'transfertool', schema=schema)
        drop_column('requests_history', 'transfertool', schema=schema)
