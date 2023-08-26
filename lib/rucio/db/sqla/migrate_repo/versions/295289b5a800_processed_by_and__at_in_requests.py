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

""" processed_by and _at in requests """

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

# Alembic revision identifiers
revision = '295289b5a800'
down_revision = 'a6eb23955c28'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('last_processed_by', sa.String(64)), schema=schema)
        add_column('requests', sa.Column('last_processed_at', sa.DateTime()), schema=schema)


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'last_processed_by', schema=schema)
        drop_column('requests', 'last_processed_at', schema=schema)
