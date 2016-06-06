# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

"""Added stuck_at column to rules

Revision ID: 102efcf145f4
Revises: 4207be2fd914
Create Date: 2014-10-07 13:31:25.347076

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '102efcf145f4'
down_revision = '70587619328'


def upgrade():
    op.add_column('rules', sa.Column('stuck_at', sa.DateTime))


def downgrade():
    op.drop_column('rules', 'stuck_at')
