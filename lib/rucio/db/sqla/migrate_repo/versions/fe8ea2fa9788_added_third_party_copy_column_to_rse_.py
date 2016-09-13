# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2016

"""Added third_party_copy column to rse_protocols

Revision ID: fe8ea2fa9788
Revises: 0437a40dbfd1
Create Date: 2016-08-25 13:26:40.642215

"""

from alembic import context, op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fe8ea2fa9788'
down_revision = '0437a40dbfd1'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.add_column('rse_protocols', sa.Column('third_party_copy', sa.Integer, server_default='0'))


def downgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_column('rse_protocols', 'third_party_copy')
