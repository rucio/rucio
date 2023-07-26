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

''' add convention table and closed_at to dids '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key, add_column,
                        create_check_constraint, drop_column, drop_table)

from rucio.common.schema import get_schema_value
from rucio.db.sqla.constants import KeyType

# Alembic revision identifiers
revision = '3082b8cef557'
down_revision = '269fee20dee9'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('dids', sa.Column('closed_at', sa.DateTime), schema=schema)
        add_column('contents_history', sa.Column('deleted_at', sa.DateTime), schema=schema)
        create_table('naming_conventions',
                     sa.Column('scope', sa.String(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('regexp', sa.String(255)),
                     sa.Column('convention_type', sa.Enum(KeyType,
                                                          name='CVT_TYPE_CHK',
                                                          create_constraint=True,
                                                          values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('NAMING_CONVENTIONS_PK', 'naming_conventions', ['scope'])
        create_foreign_key('NAMING_CONVENTIONS_SCOPE_FK', 'naming_conventions',
                           'scopes', ['scope'], ['scope'])
        create_check_constraint('NAMING_CONVENTIONS_CREATED_NN', 'naming_conventions',
                                'created_at is not null')
        create_check_constraint('NAMING_CONVENTIONS_UPDATED_NN', 'naming_conventions',
                                'updated_at is not null')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('dids', 'closed_at', schema=schema)
        drop_column('contents_history', 'deleted_at', schema=schema)
        drop_table('naming_conventions', schema=schema)
