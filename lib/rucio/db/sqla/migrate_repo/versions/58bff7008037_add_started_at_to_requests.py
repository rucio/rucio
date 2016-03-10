# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

"""Add started_at to requests

Revision ID: 58bff7008037
Revises: 2edee4a83846
Create Date: 2015-10-23 12:35:19.658347

"""

from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '58bff7008037'
down_revision = '3c9df354071b'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.add_column('requests', sa.Column('started_at', sa.DateTime))
        op.add_column('requests_history', sa.Column('started_at', sa.DateTime))


def downgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_column('requests', 'started_at')
        op.drop_column('requests_history', 'started_at')
