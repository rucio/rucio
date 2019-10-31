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
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2019


''' add staging timestamps to request '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column


# Alembic revision identifiers
revision = 'bc68e9946deb'
down_revision = '9a1b149a2044'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('staging_started_at', sa.DateTime()), schema=schema)
        add_column('requests', sa.Column('staging_finished_at', sa.DateTime()), schema=schema)
        add_column('requests_history', sa.Column('staging_started_at', sa.DateTime()), schema=schema)
        add_column('requests_history', sa.Column('staging_finished_at', sa.DateTime()), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'staging_started_at', schema=schema)
        drop_column('requests', 'staging_finished_at', schema=schema)
        drop_column('requests_history', 'staging_started_at', schema=schema)
        drop_column('requests_history', 'staging_finished_at', schema=schema)
