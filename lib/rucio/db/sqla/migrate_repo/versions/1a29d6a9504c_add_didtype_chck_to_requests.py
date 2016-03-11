# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""add didtype_chck to requests

Revision ID: 1a29d6a9504c
Revises: 436827b13f82
Create Date: 2014-10-13 13:48:56.080599

"""

from alembic import op
import sqlalchemy as sa

from rucio.db.sqla.constants import DIDType

# revision identifiers, used by Alembic.
revision = '1a29d6a9504c'
down_revision = '436827b13f82'


def upgrade():
    op.add_column('requests', sa.Column('did_type',
                                        DIDType.db_type(name='REQUESTS_DIDTYPE_CHK'),
                                        default=DIDType.FILE))

    # we don't want checks on the history table
    op.add_column('requests_history', sa.Column('did_type', sa.String(1)))


def downgrade():
    op.drop_column('requests', 'did_type')
    op.drop_column('requests_history', 'did_type')
