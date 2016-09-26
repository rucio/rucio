# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

"""asynchronous rules and rule approval

Revision ID: 1d96f484df21
Revises: 1fc15ab60d43
Create Date: 2015-07-08 16:59:23.710208

"""

from alembic import op, context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1d96f484df21'
down_revision = '3d9813fab443'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False))
        if context.get_context().dialect.name not in ('mysql'):
            op.drop_constraint('RULES_STATE_CHK', 'rules')
        op.create_check_constraint('RULES_STATE_CHK', 'rules', 'state IN (\'S\', \'R\', \'U\', \'O\', \'A\', \'I\')')


def downgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_column('rules', 'ignore_account_limit')
        op.drop_constraint('RULES_STATE_CHK', 'rules')
        op.create_check_constraint('RULES_STATE_CHK', 'rules', 'state IN (\'S\', \'R\', \'U\', \'O\')')
