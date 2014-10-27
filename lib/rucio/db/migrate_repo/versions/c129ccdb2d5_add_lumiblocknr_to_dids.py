# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""add lumiblocknr to dids

Revision ID: c129ccdb2d5
Revises: 156fb5b5a14
Create Date: 2014-10-27 15:02:17.288129

"""

# revision identifiers, used by Alembic.
revision = 'c129ccdb2d5'
down_revision = '156fb5b5a14'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('dids', sa.Column('lumiblocknr', sa.Integer()))

def downgrade():
    op.drop_column('dids', 'lumiblocknr')
