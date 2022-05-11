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

''' Add columns for third_party_copy_read and third_party_copy_write '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

# Alembic revision identifiers
revision = '2b69addda658'
down_revision = 'bc68e9946deb'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('rse_protocols', sa.Column('third_party_copy_write', sa.Integer), schema=schema)
        add_column('rse_protocols', sa.Column('third_party_copy_read', sa.Integer), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('rse_protocols', 'third_party_copy_write', schema=schema)
        drop_column('rse_protocols', 'third_party_copy_read', schema=schema)
