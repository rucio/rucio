# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""add lumiblocknr to dids

Revision ID: c129ccdb2d5
Revises: 156fb5b5a14
Create Date: 2014-10-27 15:02:17.288129

"""
from alembic.op import add_column, drop_column

from alembic import context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c129ccdb2d5'
down_revision = '156fb5b5a14'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        add_column('dids', sa.Column('lumiblocknr', sa.Integer()))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('dids', 'lumiblocknr')
