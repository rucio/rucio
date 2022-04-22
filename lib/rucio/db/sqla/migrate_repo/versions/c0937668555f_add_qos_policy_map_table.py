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

''' add qos policy map table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import create_table, create_primary_key, create_foreign_key, drop_table, create_check_constraint

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = 'c0937668555f'
down_revision = 'a193a275255c'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        create_table('rse_qos_map',
                     sa.Column('rse_id', GUID()),
                     sa.Column('qos_policy', sa.String(64)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('RSE_QOS_MAP_PK', 'rse_qos_map', ['rse_id', 'qos_policy'])
        create_check_constraint('RSE_QOS_MAP_CREATED_NN', 'rse_qos_map', 'created_at is not null')
        create_check_constraint('RSE_QOS_MAP_UPDATED_NN', 'rse_qos_map', 'updated_at is not null')
        create_foreign_key('RSE_QOS_MAP_RSE_ID_FK',
                           'rse_qos_map', 'rses',
                           ['rse_id'], ['id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql', 'mysql']:
        drop_table('rse_qos_map')
