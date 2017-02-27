# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""New account_limits table

Revision ID: d91002c5841
Revises: 469d262be19
Create Date: 2014-04-14 17:05:24.328328
"""

import sqlalchemy as sa

from alembic.op import (create_check_constraint, create_table, create_primary_key,
                        create_foreign_key, drop_constraint, drop_table)

from alembic import context

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = 'd91002c5841'
down_revision = '469d262be19'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name == 'postgresql':
        drop_constraint('ACCOUNT_LIMITS_PK', 'account_limits', type_='primary')
        drop_constraint('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits')
        drop_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits')
        drop_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits')
    drop_table('account_limits')

    create_table('account_limits',
                 sa.Column('account', sa.String(25)),
                 sa.Column('rse_id', GUID()),
                 sa.Column('bytes', sa.BigInteger),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_id'])
        create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
        create_foreign_key('ACCOUNT_LIMITS_RSE_ID_FK', 'account_limits', 'rses', ['rse_id'], ['id'])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name == 'postgresql':
        drop_constraint('ACCOUNT_LIMITS_PK', 'account_limits', type_='primary')
        drop_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits')
        drop_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits')
        drop_constraint('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits')
        drop_constraint('ACCOUNT_LIMITS_RSE_ID_FK', 'account_limits')
    drop_table('account_limits')

    create_table('account_limits',
                 sa.Column('account', sa.String(25)),
                 sa.Column('rse_expression', sa.String(255)),
                 sa.Column('name', sa.String(255)),
                 sa.Column('value', sa.BigInteger),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_expression', 'name'])
        create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
