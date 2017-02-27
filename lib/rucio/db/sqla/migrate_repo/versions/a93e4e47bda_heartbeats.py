# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""heartbeats

Revision ID: a93e4e47bda
Revises: 2af3291ec4c
Create Date: 2015-02-20 11:10:41.519438

"""

from alembic.op import (create_table, create_primary_key,
                        create_check_constraint, create_index,
                        drop_constraint, drop_index, drop_table)
from alembic import context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a93e4e47bda'
down_revision = '2af3291ec4c'


def upgrade():
    '''
    upgrade method
    '''
    create_table('heartbeats',
                 sa.Column('executable', sa.String(512)),
                 sa.Column('hostname', sa.String(128)),
                 sa.Column('pid', sa.Integer(), autoincrement=False),
                 sa.Column('thread_id', sa.BigInteger(), autoincrement=False),
                 sa.Column('thread_name', sa.String(64)),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))

    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('heartbeats_pk', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])
        create_index('heartbeats_updated_at', 'heartbeats', ['updated_at'])

        if context.get_context().dialect.name != 'mysql':
            create_check_constraint('heartbeats_created_nn', 'heartbeats', 'created_at is not null')
            create_check_constraint('heartbeats_updated_nn', 'heartbeats', 'updated_at is not null')


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':

        drop_constraint('heartbeats_pk', 'configs', type_='primary')
        drop_index('heartbeats_updated_at', 'heartbeats')

        if context.get_context().dialect.name != 'mysql':
            drop_constraint('heartbeats_created_nn', 'heartbeats', type_='check')
            drop_constraint('heartbeats_updated_nn', 'heartbeats', type_='check')

    drop_table('heartbeats')
