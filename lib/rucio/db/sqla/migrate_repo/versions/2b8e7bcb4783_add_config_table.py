# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""add config table

Revision ID: 2b8e7bcb4783
Revises: 469d262be19
Create Date: 2014-04-08 16:20:48.185087

"""

from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2b8e7bcb4783'
down_revision = 'd91002c5841'


def upgrade():
    op.create_table('configs',
                    sa.Column('section', sa.String(128)),
                    sa.Column('opt', sa.String(128)),
                    sa.Column('value', sa.String(4000)),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('configs_pk', 'configs', ['section', 'opt'])
        op.create_check_constraint('configs_created_nn', 'configs', 'created_at is not null')
        op.create_check_constraint('configs_updated_nn', 'configs', 'updated_at is not null')
    op.create_table('configs_history',
                    sa.Column('section', sa.String(128)),
                    sa.Column('opt', sa.String(128)),
                    sa.Column('value', sa.String(4000)),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('configs_history_pk', 'configs_history', ['section', 'opt', 'updated_at'])


def downgrade():
    if context.get_context().dialect.name is 'postgresql':
        op.drop_constraint('configs_pk', 'configs', type_='primary')
        op.drop_constraint('configs_created_nn', 'configs', type_='check')
        op.drop_constraint('configs_updated_nn', 'configs', type_='check')
    op.drop_table('configs')
    if context.get_context().dialect.name is 'postgresql':
        op.drop_constraint('configs_history_pk', 'configs_history', type_='check')
    op.drop_table('configs_history')
