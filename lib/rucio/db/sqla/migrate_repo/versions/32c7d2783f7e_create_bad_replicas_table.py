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

''' create bad replicas table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)

from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '32c7d2783f7e'
down_revision = '384b96aa0f60'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('bad_replicas',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('reason', sa.String(255)),
                     sa.Column('state', sa.String(1)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('BAD_REPLICAS_STATE_PK', 'bad_replicas', ['scope', 'name', 'rse_id', 'created_at'])
        create_check_constraint('BAD_REPLICAS_SCOPE_NN', 'bad_replicas', 'scope is not null')
        create_check_constraint('BAD_REPLICAS_NAME_NN', 'bad_replicas', 'name is not null')
        create_check_constraint('BAD_REPLICAS_RSE_ID_NN', 'bad_replicas', 'rse_id is not null')
        create_foreign_key('BAD_REPLICAS_ACCOUNT_FK', 'bad_replicas', 'accounts', ['account'], ['account'])
        create_index('BAD_REPLICAS_STATE_IDX', 'bad_replicas', ['rse_id', 'state'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('bad_replicas')
