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

''' transfer_stats table '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_index, create_check_constraint, drop_table)

from rucio.db.sqla.types import GUID
# Alembic revision identifiers
revision = 'a08fa8de1545'
down_revision = '4df2c5ddabc0'


def upgrade():
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('transfer_stats',
                     sa.Column('id', GUID()),
                     sa.Column('resolution', sa.Integer),
                     sa.Column('timestamp', sa.DateTime),
                     sa.Column('dest_rse_id', GUID()),
                     sa.Column('src_rse_id', GUID()),
                     sa.Column('activity', sa.String(50)),
                     sa.Column('files_done', sa.BigInteger),
                     sa.Column('bytes_done', sa.BigInteger),
                     sa.Column('files_failed', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('TRANSFER_STATS_PK', 'transfer_stats', ['id'])
        create_foreign_key('TRANSFER_STATS_DEST_RSE_FK', 'transfer_stats', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('TRANSFER_STATS_SRC_RSE_FK', 'transfer_stats', 'rses', ['src_rse_id'], ['id'])
        create_index('TRANSFER_STATS_KEY_IDX', 'transfer_stats', ['resolution', 'timestamp', 'dest_rse_id', 'src_rse_id', 'activity'])
        create_check_constraint('TRANSFER_STATS_CREATED_NN', 'transfer_stats', 'created_at is not null')
        create_check_constraint('TRANSFER_STATS_UPDATED_NN', 'transfer_stats', 'updated_at is not null')


def downgrade():

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('transfer_stats')
