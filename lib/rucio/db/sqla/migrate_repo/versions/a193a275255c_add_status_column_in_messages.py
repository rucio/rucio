# Copyright 2014-2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020

''' Add status column in messages '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

# Alembic revision identifiers
revision = 'a193a275255c'
down_revision = 'a118956323f8'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        add_column('messages', sa.Column('services', sa.String(2048)), schema=schema[:-1])
        add_column('messages_history', sa.Column('services', sa.String(2048)), schema=schema[:-1])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        drop_column('messages', 'services', schema=schema[:-1])
        drop_column('messages_history', 'services', schema=schema[:-1])
