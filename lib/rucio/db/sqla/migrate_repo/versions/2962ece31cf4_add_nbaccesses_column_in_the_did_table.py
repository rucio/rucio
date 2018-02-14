'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2018

Add access_cnt column in the DID table

Revision ID: 2962ece31cf4
Revises: 94a5961ddbf2
Create Date: 2018-02-13 15:23:01.963771

'''
from alembic.op import add_column, drop_column

from alembic import context

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2962ece31cf4'  # pylint: disable=invalid-name
down_revision = '94a5961ddbf2'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':  # pylint: disable=no-member
        add_column('dids', sa.Column('access_cnt', sa.Integer, server_default='0'))
        add_column('deleted_dids', sa.Column('access_cnt', sa.Integer, server_default='0'))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':  # pylint: disable=no-member
        drop_column('dids', 'access_cnt')
        drop_column('deleted_dids', 'access_cnt')
