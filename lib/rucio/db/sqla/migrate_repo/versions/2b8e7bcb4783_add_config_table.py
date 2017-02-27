# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""add config table

Revision ID: 2b8e7bcb4783
Revises: 469d262be19
Create Date: 2014-04-08 16:20:48.185087

"""

from alembic import context
from alembic.op import (create_table, create_primary_key,
                        create_check_constraint,
                        drop_constraint, drop_table)
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2b8e7bcb4783'
down_revision = 'd91002c5841'


def upgrade():
    '''
    upgrade method
    '''
    create_table('configs',
                 sa.Column('section', sa.String(128)),
                 sa.Column('opt', sa.String(128)),
                 sa.Column('value', sa.String(4000)),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('configs_pk', 'configs', ['section', 'opt'])
        create_check_constraint('configs_created_nn', 'configs', 'created_at is not null')
        create_check_constraint('configs_updated_nn', 'configs', 'updated_at is not null')
    create_table('configs_history',
                 sa.Column('section', sa.String(128)),
                 sa.Column('opt', sa.String(128)),
                 sa.Column('value', sa.String(4000)),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('configs_history_pk', 'configs_history', ['section', 'opt', 'updated_at'])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name is 'postgresql':
        drop_constraint('configs_pk', 'configs', type_='primary')
        drop_constraint('configs_created_nn', 'configs', type_='check')
        drop_constraint('configs_updated_nn', 'configs', type_='check')
    drop_table('configs')
    if context.get_context().dialect.name is 'postgresql':
        drop_constraint('configs_history_pk', 'configs_history', type_='check')
    drop_table('configs_history')
