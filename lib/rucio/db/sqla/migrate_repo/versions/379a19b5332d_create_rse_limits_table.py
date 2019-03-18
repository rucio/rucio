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

''' create rse transfer limits table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, drop_table)

from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '379a19b5332d'
down_revision = '58bff7008037'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('rse_transfer_limits',
                     sa.Column('rse_id', GUID()),
                     sa.Column('activity', sa.String(50)),
                     sa.Column('rse_expression', sa.String(3000)),
                     sa.Column('max_transfers', sa.BigInteger),
                     sa.Column('transfers', sa.BigInteger),
                     sa.Column('waitings', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('RSE_TRANSFER_LIMITS_PK', 'rse_transfer_limits', ['rse_id', 'activity'])
        create_check_constraint('RSE_TRANSFER_LIMITS_CREATED_NN', 'rse_transfer_limits', 'created_at is not null')
        create_check_constraint('RSE_TRANSFER_LIMITS_UPDATED_NN', 'rse_transfer_limits', 'updated_at is not null')
        create_foreign_key('RSE_TRANSFER_LIMITS_RSE_ID_FK', 'rse_transfer_limits', 'rses', ['rse_id'], ['id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('rse_transfer_limits')

    elif context.get_context().dialect.name == 'postgresql':
        # drop_constraint('RSE_TRANSFER_LIMITS_PK', 'rse_transfer_limits', type_='primary')
        # drop_constraint('RSE_TRANSFER_LIMITS_CREATED_NN', 'rse_transfer_limits')
        # drop_constraint('RSE_TRANSFER_LIMITS_UPDATED_NN', 'rse_transfer_limits')
        # drop_constraint('RSE_TRANSFER_LIMITS_RSE_ID_FK', 'rse_transfer_limits')
        pass
