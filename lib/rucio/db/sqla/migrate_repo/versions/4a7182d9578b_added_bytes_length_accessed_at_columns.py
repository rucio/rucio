# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

"""Added bytes, length, accessed_at columns

Revision ID: 4a7182d9578b
Revises: c129ccdb2d5
Create Date: 2014-11-13 10:03:13.055583

"""
from alembic import context
from alembic.op import add_column, drop_column
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4a7182d9578b'
down_revision = 'c129ccdb2d5'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        add_column('dataset_locks', sa.Column('length', sa.BigInteger()))
        add_column('dataset_locks', sa.Column('bytes', sa.BigInteger()))
        add_column('dataset_locks', sa.Column('accessed_at', sa.DateTime()))
        add_column('dids', sa.Column('accessed_at', sa.DateTime()))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('dataset_locks', 'length')
        drop_column('dataset_locks', 'bytes')
        drop_column('dataset_locks', 'accessed_at')
        drop_column('dids', 'accessed_at')
