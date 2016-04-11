# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""New account_limits table

Revision ID: d91002c5841
Revises: 469d262be19
Create Date: 2014-04-14 17:05:24.328328
"""

import sqlalchemy as sa

from alembic import context, op

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = 'd91002c5841'
down_revision = '469d262be19'


def upgrade():
    if context.get_context().dialect.name == 'postgresql':
        op.drop_constraint('ACCOUNT_LIMITS_PK', 'account_limits', type_='primary')
        op.drop_constraint('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits')
        op.drop_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits')
        op.drop_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits')
    op.drop_table('account_limits')

    op.create_table('account_limits',
                    sa.Column('account', sa.String(25)),
                    sa.Column('rse_id', GUID()),
                    sa.Column('bytes', sa.BigInteger),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_id'])
        op.create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        op.create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        op.create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
        op.create_foreign_key('ACCOUNT_LIMITS_RSE_ID_FK', 'account_limits', 'rses', ['rse_id'], ['id'])


def downgrade():
    if context.get_context().dialect.name == 'postgresql':
        op.drop_constraint('ACCOUNT_LIMITS_PK', 'account_limits', type_='primary')
        op.drop_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits')
        op.drop_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits')
        op.drop_constraint('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits')
        op.drop_constraint('ACCOUNT_LIMITS_RSE_ID_FK', 'account_limits')
    op.drop_table('account_limits')

    op.create_table('account_limits',
                    sa.Column('account', sa.String(25)),
                    sa.Column('rse_expression', sa.String(255)),
                    sa.Column('name', sa.String(255)),
                    sa.Column('value', sa.BigInteger),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('ACCOUNT_LIMITS_PK', 'account_limits', ['account', 'rse_expression', 'name'])
        op.create_check_constraint('ACCOUNT_LIMITS_CREATED_NN', 'account_limits', 'created_at is not null')
        op.create_check_constraint('ACCOUNT_LIMITS_UPDATED_NN', 'account_limits', 'updated_at is not null')
        op.create_foreign_key('ACCOUNT_LIMITS_ACCOUNT_FK', 'account_limits', 'accounts', ['account'], ['account'])
