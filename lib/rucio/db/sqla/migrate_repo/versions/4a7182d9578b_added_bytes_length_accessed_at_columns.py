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

from alembic import op, context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4a7182d9578b'
down_revision = 'c129ccdb2d5'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.add_column('dataset_locks', sa.Column('length', sa.BigInteger()))
        op.add_column('dataset_locks', sa.Column('bytes', sa.BigInteger()))
        op.add_column('dataset_locks', sa.Column('accessed_at', sa.DateTime()))
        op.add_column('dids', sa.Column('accessed_at', sa.DateTime()))


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_column('dataset_locks', 'length')
        op.drop_column('dataset_locks', 'bytes')
        op.drop_column('dataset_locks', 'accessed_at')
        op.drop_column('dids', 'accessed_at')
