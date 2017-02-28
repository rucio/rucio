# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""Added share to rules

Revision ID: 52fd9f4916fa
Revises: 4a2cbedda8b9
Create Date: 2014-07-15 17:57:58.189448

"""
from alembic import context
from alembic.op import add_column, drop_column
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '52fd9f4916fa'
down_revision = '4a2cbedda8b9'


def upgrade():
    '''
    upgrade method
    '''
    add_column('rules', sa.Column('activity', sa.String(50)))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('rules', 'activity')
