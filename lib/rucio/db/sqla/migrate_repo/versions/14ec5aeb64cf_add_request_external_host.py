# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""add request external_host

Revision ID: 14ec5aeb64cf
Revises: 52fd9f4916fa
Create Date: 2014-08-22 13:25:22.132950

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '14ec5aeb64cf'
down_revision = '52fd9f4916fa'


def upgrade():
    op.add_column('requests', sa.Column('external_host', sa.String(256)))


def downgrade():
    op.drop_column('requests', 'external_host')
