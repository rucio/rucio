# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""Add ignore_availability column to rules

Revision ID: 271a46ea6244
Revises: d6dceb1de2d
Create Date: 2015-01-13 15:32:20.732545

"""
from alembic import context
from alembic.op import add_column, drop_column

import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '271a46ea6244'
down_revision = 'd6dceb1de2d'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ['sqlite']:
        add_column('rules', sa.Column('ignore_availability', sa.Boolean(name='RULES_IGNORE_AVAILABILITY_CHK'), default=False))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ['sqlite']:
        drop_column('rules', 'ignore_availability')
