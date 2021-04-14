# Copyright 2013-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2021

''' Extending columns for filter and replication_rules in subscriptions '''

import sqlalchemy as sa

from alembic import context
from alembic.op import alter_column


# Alembic revision identifiers
revision = 'e138c364ebd0'
down_revision = 'f85a2962b021'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        alter_column('subscriptions', 'filter', existing_type=sa.String(2048), type_=sa.String(4000), schema=schema)
        alter_column('subscriptions', 'replication_rules', existing_type=sa.String(1024), type_=sa.String(4000), schema=schema)
        alter_column('subscriptions_history', 'filter', existing_type=sa.String(2048), type_=sa.String(4000), schema=schema)
        alter_column('subscriptions_history', 'replication_rules', existing_type=sa.String(1024), type_=sa.String(4000), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        alter_column('subscriptions', 'filter', existing_type=sa.String(4000), type_=sa.String(2048), schema=schema)
        alter_column('subscriptions', 'replication_rules', existing_type=sa.String(4000), type_=sa.String(1024), schema=schema)
        alter_column('subscriptions_history', 'filter', existing_type=sa.String(4000), type_=sa.String(2048), schema=schema)
        alter_column('subscriptions_history', 'replication_rules', existing_type=sa.String(4000), type_=sa.String(1024), schema=schema)
