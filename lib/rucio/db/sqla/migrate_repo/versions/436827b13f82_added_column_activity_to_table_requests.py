# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2017

"""added column activity to table requests

Revision ID: 436827b13f82
Revises: 102efcf145f4
Create Date: 2014-10-10 10:20:15.597871

"""

from alembic.op import add_column, drop_column
from alembic import context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '436827b13f82'
down_revision = '102efcf145f4'


def upgrade():
    '''
    upgrade method
    '''
    add_column('requests', sa.Column('activity', sa.String(50)))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('requests', 'activity')
