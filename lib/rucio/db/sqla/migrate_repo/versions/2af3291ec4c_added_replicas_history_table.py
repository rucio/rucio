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

''' added replicas history table '''

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, drop_constraint, drop_table)

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '2af3291ec4c'
down_revision = '32c7d2783f7e'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('replicas_history',
                     sa.Column('rse_id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('bytes', sa.BigInteger))

        create_primary_key('REPLICAS_HIST_PK', 'replicas_history', ['rse_id', 'scope', 'name'])
        create_foreign_key('REPLICAS_HIST_RSE_ID_FK', 'replicas_history', 'rses', ['rse_id'], ['id'])
        create_check_constraint('REPLICAS_HIST_SIZE_NN', 'replicas_history', 'bytes IS NOT NULL')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('replicas_history')

    elif context.get_context().dialect.name == 'postgresql':
        drop_constraint('REPLICAS_HIST_PK', 'replicas_history', type_='primary')
        drop_constraint('REPLICAS_HIST_RSE_ID_FK', 'replicas_history')
        drop_constraint('REPLICAS_HIST_SIZE_NN', 'replicas_history')
        drop_table('replicas_history')
