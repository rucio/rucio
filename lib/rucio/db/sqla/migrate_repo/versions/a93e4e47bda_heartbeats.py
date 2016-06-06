# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

"""heartbeats

Revision ID: a93e4e47bda
Revises: 2af3291ec4c
Create Date: 2015-02-20 11:10:41.519438

"""

from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a93e4e47bda'
down_revision = '2af3291ec4c'


def upgrade():
    op.create_table('heartbeats',
                    sa.Column('executable', sa.String(512)),
                    sa.Column('hostname', sa.String(128)),
                    sa.Column('pid', sa.Integer(), autoincrement=False),
                    sa.Column('thread_id', sa.BigInteger(), autoincrement=False),
                    sa.Column('thread_name', sa.String(64)),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))

    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('heartbeats_pk', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])
        op.create_index('heartbeats_updated_at', 'heartbeats', ['updated_at'])

        if context.get_context().dialect.name != 'mysql':
            op.create_check_constraint('heartbeats_created_nn', 'heartbeats', 'created_at is not null')
            op.create_check_constraint('heartbeats_updated_nn', 'heartbeats', 'updated_at is not null')


def downgrade():

    if context.get_context().dialect.name != 'sqlite':

        op.drop_constraint('heartbeats_pk', 'configs', type_='primary')
        op.drop_index('heartbeats_updated_at', 'heartbeats')

        if context.get_context().dialect.name != 'mysql':
            op.drop_constraint('heartbeats_created_nn', 'heartbeats', type_='check')
            op.drop_constraint('heartbeats_updated_nn', 'heartbeats', type_='check')

    op.drop_table('heartbeats')
