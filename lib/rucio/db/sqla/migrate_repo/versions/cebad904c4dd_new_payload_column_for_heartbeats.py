# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Martin Barisits <martin.barisits@cern.ch>, 2019

''' New payload column for heartbeats '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column, create_index, drop_index

from rucio.db.sqla.models import String

# Alembic revision identifiers
revision = 'cebad904c4dd'
down_revision = 'b7d287de34fd'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_index('HEARTBEATS_UPDATED_AT', 'heartbeats')
        add_column('heartbeats', sa.Column('payload', String(3000)), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        create_index('HEARTBEATS_UPDATED_AT', 'heartbeats', ['updated_at'])
        drop_column('heartbeats', 'payload', schema=schema)
