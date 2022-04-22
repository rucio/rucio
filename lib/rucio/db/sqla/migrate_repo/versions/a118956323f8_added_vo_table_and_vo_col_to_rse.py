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

''' Added vo table and vo col to rse '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (add_column, create_primary_key, create_table, create_unique_constraint,
                        drop_column, drop_constraint, drop_table, bulk_insert)


def String(*arg, **kw):
    kw['convert_unicode'] = True
    return sa.String(*arg, **kw)


# Alembic revision identifiers
revision = 'a118956323f8'
down_revision = 'd1189a09c6e0'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        # add a vo table
        vos = create_table('vos',
                           sa.Column('vo', String(3)),
                           sa.Column('description', String(255)),
                           sa.Column('email', String(255)),
                           sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                           sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                           schema=schema)
        create_primary_key('VOS_PK', 'vos', ['vo'])

        # create base vo
        bulk_insert(vos, [{'vo': 'def',
                           'description': 'Base VO',
                           'email': 'N/A'}])

        # add a vo column
        add_column('rses', sa.Column('vo', String(3), sa.ForeignKey('vos.vo', name='RSES_VOS_FK'), nullable=False, server_default='def'), schema=schema)

        # change unique constraint: (rse) -> (rse,vo)
        drop_constraint('RSES_RSE_UQ', 'rses', type_='unique', schema=schema)
        create_unique_constraint('RSES_RSE_UQ', 'rses', ['rse', 'vo'], schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''

        # change unique constraint: (rse, vo) -> (rse)
        drop_constraint('RSES_RSE_UQ', 'rses', type_='unique', schema=schema)
        create_unique_constraint('RSES_RSE_UQ', 'rses', ['rse'], schema=schema)

        # drop vo column
        drop_constraint('RSES_VOS_FK', 'rses', type_='foreignkey', schema=schema)
        drop_column('rses', 'vo', schema=schema)

        # drop vo table
        drop_table('vos', schema=schema)
