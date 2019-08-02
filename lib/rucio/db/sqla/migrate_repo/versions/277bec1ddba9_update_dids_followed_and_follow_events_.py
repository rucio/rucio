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
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019

''' update dids_followed and follow_events table '''

import sqlalchemy as sa
import datetime

from alembic import context
from alembic.op import add_column, drop_column


# Alembic revision identifiers
revision = '277bec1ddba9'
down_revision = '7541902bf173'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('dids_followed', sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow), schema=schema)
        add_column('dids_followed', sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow), schema=schema)
        add_column('follow_events', sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow), schema=schema)
        add_column('follow_events', sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('dids_followed', 'updated_at', schema=schema)
        drop_column('dids_followed', 'created_at', schema=schema)
        drop_column('follow_events', 'updated_at', schema=schema)
        drop_column('follow_events', 'created_at', schema=schema)
