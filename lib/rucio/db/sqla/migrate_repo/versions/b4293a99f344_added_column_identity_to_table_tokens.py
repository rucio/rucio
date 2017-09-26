'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017

added column identity to table tokens

Revision ID: b4293a99f344
Revises: 3ac1660a1a72
Create Date: 2017-08-29 10:06:07.184267

'''
from alembic.op import add_column, drop_column

from alembic import context

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b4293a99f344'  # pylint: disable=invalid-name
down_revision = '3ac1660a1a72'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        add_column('tokens', sa.Column('identity', sa.String(255)))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('tokens', 'identity')
