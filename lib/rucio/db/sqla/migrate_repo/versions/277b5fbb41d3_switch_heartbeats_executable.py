# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

"""switch heartbeats executable

Revision ID: 277b5fbb41d3
Revises: 40ad39ce3160
Create Date: 2015-05-06 15:31:50.256448

"""

from alembic import op, context
import sqlalchemy as sa

from rucio.db.sqla.models import String

# revision identifiers, used by Alembic.
revision = '277b5fbb41d3'
down_revision = '44278720f774'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_constraint('heartbeats_pk', 'heartbeats', type_='primary')
        op.drop_column('heartbeats', 'executable')
        op.add_column('heartbeats', sa.Column('executable', String(64)))
        op.add_column('heartbeats', sa.Column('readable', String(4000)))
        op.create_primary_key('HEARTBEATS_PK', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])


def downgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_constraint('heartbeats_pk', 'heartbeats', type_='primary')
        op.drop_column('heartbeats', 'executable')
        op.drop_column('heartbeats', 'readable')
        op.add_column('heartbeats', sa.Column('executable', String(767)))
        op.create_primary_key('HEARTBEATS_PK', 'heartbeats', ['executable', 'hostname', 'pid', 'thread_id'])
