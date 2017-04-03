"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Martin Barisits, <martin.barisits@cern.ch>, 2015
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

Add repair_cnt to locks

Revision ID: 269fee20dee9
Revises: 3d9813fab443
Create Date: 2015-07-13 17:52:33.103379

"""

from alembic import context
from alembic.op import add_column, drop_column

import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '269fee20dee9'  # pylint:disable=invalid-name
down_revision = '1d96f484df21'  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ['sqlite']:
        add_column('locks', sa.Column('repair_cnt', sa.BigInteger()))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ['sqlite']:
        drop_column('locks', 'repair_cnt')
