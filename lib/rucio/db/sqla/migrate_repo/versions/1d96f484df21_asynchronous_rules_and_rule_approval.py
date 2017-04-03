# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017


"""asynchronous rules and rule approval

Revision ID: 1d96f484df21
Revises: 1fc15ab60d43
Create Date: 2015-07-08 16:59:23.710208

"""
from alembic.op import (add_column, create_check_constraint,
                        drop_constraint, drop_column)
from alembic import context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1d96f484df21'  # pylint: disable=invalid-name
down_revision = '3d9813fab443'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False))
        if context.get_context().dialect.name not in ('mysql'):
            drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint('RULES_STATE_CHK', 'rules', 'state IN (\'S\', \'R\', \'U\', \'O\', \'A\', \'I\')')


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):
        drop_column('rules', 'ignore_account_limit')
        drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint('RULES_STATE_CHK', 'rules', 'state IN (\'S\', \'R\', \'U\', \'O\')')
