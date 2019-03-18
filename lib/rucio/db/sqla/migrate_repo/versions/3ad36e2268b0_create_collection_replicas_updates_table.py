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
# - Martin Barisits <martin.barisits@cern.ch>, 2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' create collection_replicas_updates table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, add_column,
                        create_check_constraint, create_index,
                        drop_constraint, drop_column, drop_table, drop_index)

from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '3ad36e2268b0'
down_revision = '42db2617c364'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('collection_replicas', sa.Column('available_replicas_cnt', sa.BigInteger()), schema=schema)
        add_column('collection_replicas', sa.Column('available_bytes', sa.BigInteger()), schema=schema)

        create_table('updated_col_rep',
                     sa.Column('id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('did_type', DIDType.db_type()),
                     sa.Column('rse_id', GUID()),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('UPDATED_COL_REP_PK', 'updated_col_rep', ['id'])
        create_check_constraint('UPDATED_COL_REP_SCOPE_NN', 'updated_col_rep', 'scope IS NOT NULL')
        create_check_constraint('UPDATED_COL_REP_NAME_NN', 'updated_col_rep', 'name IS NOT NULL')
        create_index('UPDATED_COL_REP_SNR_IDX', 'updated_col_rep', ['scope', 'name', 'rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('collection_replicas', 'available_replicas_cnt', schema=schema)
        drop_column('collection_replicas', 'available_bytes', schema=schema)
        drop_table('updated_col_rep')

    elif context.get_context().dialect.name == 'mysql':
        drop_column('collection_replicas', 'available_replicas_cnt')
        drop_column('collection_replicas', 'available_bytes')
        drop_constraint('UPDATED_COL_REP_PK', 'updated_col_rep', type_='primary')
        drop_index('UPDATED_COL_REP_SNR_IDX', 'updated_col_rep')
        drop_table('updated_col_rep')
