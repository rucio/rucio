# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <jbogadog@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""add source to requests and requests_history

Revision ID: 2edee4a83846
Revises: 2f648fc909f3
Create Date: 2015-10-06 10:51:43.473893

"""

from alembic import context
from alembic.op import add_column, drop_column

import sqlalchemy as sa
from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '2edee4a83846'
down_revision = '2f648fc909f3'


def upgrade():
    '''
    upgrade method
    '''
    add_column('requests', sa.Column('source_rse_id', GUID()))
    add_column('requests_history', sa.Column('source_rse_id', GUID()))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('requests', 'source_rse_id')
        drop_column('requests_history', 'source_rse_id')
