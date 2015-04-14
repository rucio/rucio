# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

"""add_submitted_at_to_requests_table

Revision ID: 2ba5229cb54c
Revises: 22d887e4ec0a
Create Date: 2015-04-14 15:56:22.772281

"""

# revision identifiers, used by Alembic.
revision = '2ba5229cb54c'
down_revision = '22d887e4ec0a'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('requests', sa.Column('submitted_at', sa.DateTime()))


def downgrade():
    op.drop_column('requests', 'submitted_at')
