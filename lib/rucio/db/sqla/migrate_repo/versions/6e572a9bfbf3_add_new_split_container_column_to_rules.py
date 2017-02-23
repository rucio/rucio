# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2016

"""add new split_container column to rules

Revision ID: 6e572a9bfbf3
Revises: 914b8f02df38
Create Date: 2016-10-31 16:20:50.973761

"""

from alembic import context, op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6e572a9bfbf3'
down_revision = '914b8f02df38'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.add_column('rules', sa.Column('split_container', sa.Boolean(name='RULES_SPLIT_CONTAINER_CHK'), default=False))
        op.add_column('rules_hist_recent', sa.Column('split_container', sa.Boolean()))
        op.add_column('rules_history', sa.Column('split_container', sa.Boolean()))


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_column('rules', 'split_container')
        op.drop_column('rules_hist_recent', 'split_container')
        op.drop_column('rules_history', 'split_container')
