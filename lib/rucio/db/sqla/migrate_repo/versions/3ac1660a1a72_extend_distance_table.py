'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
 - Cedric Serfon <cedric.serfon@cern.ch>, 2017

Extend distance table

Revision ID: 3ac1660a1a72
Revises: 5673b4b6e843
Create Date: 2017-08-24 14:45:47.731310

'''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column
from sqlalchemy import Integer

# revision identifiers, used by Alembic.
revision = '3ac1660a1a72'  # pylint: disable=invalid-name
down_revision = '5673b4b6e843'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    add_column('distances', sa.Column('packet_loss', Integer))
    add_column('distances', sa.Column('latency', Integer))
    add_column('distances', sa.Column('mbps_file', Integer))
    add_column('distances', sa.Column('mbps_link', Integer))
    add_column('distances', sa.Column('queued_total', Integer))
    add_column('distances', sa.Column('done_1h', Integer))
    add_column('distances', sa.Column('done_6h', Integer))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('distances', 'packet_loss')
        drop_column('distances', 'latency')
        drop_column('distances', 'mbps_file')
        drop_column('distances', 'mbps_link')
        drop_column('distances', 'queued_total')
        drop_column('distances', 'done_1h')
        drop_column('distances', 'done_6h')
