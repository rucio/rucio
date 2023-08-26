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

''' introduce transfer limits '''
import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_index, create_check_constraint, drop_table)

from rucio.db.sqla.constants import TransferLimitDirection
from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '13d4f70c66a9'
down_revision = '83f991c63a93'


def upgrade():
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('rse_transfer_limits')

        create_table('transfer_limits',
                     sa.Column('id', GUID()),
                     sa.Column('rse_expression', sa.String(3000)),
                     sa.Column('activity', sa.String(50)),
                     sa.Column('direction', sa.Enum(TransferLimitDirection, name='TRANSFER_LIMITS_DIRECTION_TYPE_CHK',
                                                    create_constraint=True,
                                                    values_callable=lambda obj: [e.value for e in obj]),
                               default=TransferLimitDirection.DESTINATION),
                     sa.Column('max_transfers', sa.BigInteger),
                     sa.Column('volume', sa.BigInteger),
                     sa.Column('deadline', sa.BigInteger),
                     sa.Column('strategy', sa.String(25)),
                     sa.Column('transfers', sa.BigInteger),
                     sa.Column('waitings', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('TRANSFER_LIMITS_PK', 'transfer_limits', ['id'])
        create_index('TRANSFER_LIMITS_SELECTORS_IDX', 'transfer_limits', ['rse_expression', 'activity'])
        create_check_constraint('TRANSFER_LIMITS_RSE_EXPRESSION_NN', 'transfer_limits', 'rse_expression is not null')
        create_check_constraint('TRANSFER_LIMITS_CREATED_NN', 'transfer_limits', 'created_at is not null')
        create_check_constraint('TRANSFER_LIMITS_UPDATED_NN', 'transfer_limits', 'updated_at is not null')

        create_table('rse_transfer_limits',
                     sa.Column('limit_id', GUID()),
                     sa.Column('rse_id', GUID()),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('RSE_TRANSFER_LIMITS_PK', 'rse_transfer_limits', ['limit_id', 'rse_id'])
        create_foreign_key('RSE_TRANSFER_LIMITS_RSE_ID_FK', 'rse_transfer_limits', 'rses', ['rse_id'], ['id'])
        create_foreign_key('RSE_TRANSFER_LIMITS_LIMIT_ID_FK', 'rse_transfer_limits', 'transfer_limits', ['limit_id'], ['id'])
        create_check_constraint('RSE_TRANSFER_LIMITS_CREATED_NN', 'rse_transfer_limits', 'created_at is not null')
        create_check_constraint('RSE_TRANSFER_LIMITS_UPDATED_NN', 'rse_transfer_limits', 'updated_at is not null')


def downgrade():

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('rse_transfer_limits')
        drop_table('transfer_limits')

        create_table('rse_transfer_limits',
                     sa.Column('rse_id', GUID()),
                     sa.Column('activity', sa.String(50)),
                     sa.Column('rse_expression', sa.String(3000)),
                     sa.Column('max_transfers', sa.BigInteger),
                     sa.Column('volume', sa.BigInteger),
                     sa.Column('deadline', sa.BigInteger),
                     sa.Column('strategy', sa.String(25)),
                     sa.Column('direction', sa.String(25)),
                     sa.Column('transfers', sa.BigInteger),
                     sa.Column('waitings', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('RSE_TRANSFER_LIMITS_PK', 'rse_transfer_limits', ['rse_id', 'activity'])
        create_foreign_key('RSE_TRANSFER_LIMITS_RSE_ID_FK', 'rse_transfer_limits', 'rses', ['rse_id'], ['id'])
        create_check_constraint('RSE_TRANSFER_LIMITS_CREATED_NN', 'rse_transfer_limits', 'created_at is not null')
        create_check_constraint('RSE_TRANSFER_LIMITS_UPDATED_NN', 'rse_transfer_limits', 'updated_at is not null')
