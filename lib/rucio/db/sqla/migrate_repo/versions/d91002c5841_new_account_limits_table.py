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

''' new account_limits table '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_check_constraint, create_table, create_primary_key,
                        create_foreign_key, drop_table)

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = 'd91002c5841'
down_revision = '469d262be19'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_table('account_limits')

        create_table('account_limits',
                     sa.Column('account', sa.String(25)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_id'])
        create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
        create_foreign_key('ACCOUNT_LIMITS_RSE_ID_FK', 'account_limits', 'rses', ['rse_id'], ['id'])

    elif context.get_context().dialect.name == 'mysql':
        drop_table('account_limits')

        create_table('account_limits',
                     sa.Column('account', sa.String(25)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_id'])
        create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
        create_foreign_key('ACCOUNT_LIMITS_RSE_ID_FK', 'account_limits', 'rses', ['rse_id'], ['id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('account_limits')

        create_table('account_limits',
                     sa.Column('account', sa.String(25)),
                     sa.Column('rse_expression', sa.String(255)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('value', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_expression', 'name'])
        create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])

    elif context.get_context().dialect.name == 'mysql':
        drop_table('account_limits')

        create_table('account_limits',
                     sa.Column('account', sa.String(25)),
                     sa.Column('rse_expression', sa.String(255)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('value', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_expression', 'name'])
        create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
