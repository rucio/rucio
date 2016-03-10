# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

"""Added replicas history table

Revision ID: 2af3291ec4c
Revises: 32c7d2783f7e
Create Date: 2015-02-18 11:47:12.455156

"""

from alembic import context, op
import sqlalchemy as sa

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '2af3291ec4c'
down_revision = '32c7d2783f7e'


def upgrade():
    op.create_table('replicas_history',
                    sa.Column('rse_id', GUID()),
                    sa.Column('scope', sa.String(25)),
                    sa.Column('name', sa.String(255)),
                    sa.Column('bytes', sa.BigInteger))
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('REPLICAS_HIST_PK', 'replicas_history', ['rse_id', 'scope', 'name'])
        # op.create_foreign_key('REPLICAS_HIST_LFN_FK', 'replicas_history', 'dids', ['scope', 'name'], ['scope', 'name'])
        op.create_foreign_key('REPLICAS_HIST_RSE_ID_FK', 'replicas_history', 'rses', ['rse_id'], ['id'])
        op.create_check_constraint('REPLICAS_HIST_SIZE_NN', 'replicas_history', 'bytes IS NOT NULL')


def downgrade():
    if context.get_context().dialect.name == 'postgresql':
        op.drop_constraint('REPLICAS_HIST_PK', 'replicas_history', type_='primary')
        # op.drop_constraint('REPLICAS_HIST_LFN_FK', 'replicas_history')
        op.drop_constraint('REPLICAS_HIST_RSE_ID_FK', 'replicas_history')
        op.drop_constraint('REPLICAS_HIST_SIZE_NN', 'replicas_history')
    op.drop_table('replicas_history')
