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

''' correct rse_expression length '''

import sqlalchemy as sa

from alembic import context
from alembic.op import alter_column

# Alembic revision identifiers
revision = '83f991c63a93'
down_revision = '2190e703eb6e'


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        alter_column('rules_hist_recent', 'rse_expression', existing_type=sa.String(255), type_=sa.String(3000), schema=schema)
        alter_column('rules_history', 'rse_expression', existing_type=sa.String(255), type_=sa.String(3000), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        alter_column('rules_hist_recent', 'rse_expression', existing_type=sa.String(3000), type_=sa.String(255), schema=schema)
        alter_column('rules_history', 'rse_expression', existing_type=sa.String(3000), type_=sa.String(255), schema=schema)
