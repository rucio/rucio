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
# - Wen Guan <wen.guan@cern.ch>, 2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' create distance table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)

from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '4783c1f49cb4'
down_revision = '277b5fbb41d3'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('distances',
                     sa.Column('src_rse_id', GUID()),
                     sa.Column('dest_rse_id', GUID()),
                     sa.Column('ranking', sa.Integer),
                     sa.Column('agis_distance', sa.Integer),
                     sa.Column('geoip_distance', sa.Integer),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('DISTANCES_PK', 'distances', ['src_rse_id', 'dest_rse_id'])
        create_foreign_key('DISTANCES_SRC_RSES_FK', 'distances', 'rses', ['src_rse_id'], ['id'])
        create_foreign_key('DISTANCES_DEST_RSES_FK', 'distances', 'rses', ['dest_rse_id'], ['id'])
        create_check_constraint('DISTANCES_CREATED_NN', 'distances', 'created_at is not null')
        create_check_constraint('DISTANCES_UPDATED_NN', 'distances', 'updated_at is not null')
        create_index('DISTANCES_DEST_RSEID_IDX', 'distances', ['dest_rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('distances')
