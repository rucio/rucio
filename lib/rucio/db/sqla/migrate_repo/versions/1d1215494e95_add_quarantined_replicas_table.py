# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2016

"""Add quarantined_replicas table

Revision ID: 1d1215494e95
Revises: 575767d9f89
Create Date: 2016-03-11 15:14:44.813821

"""

from alembic import context, op
import sqlalchemy as sa

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '1d1215494e95'
down_revision = '575767d9f89'


def upgrade():
    op.create_table('quarantined_replicas',
                    sa.Column('rse_id', GUID()),
                    sa.Column('path', sa.String(1024)),
                    sa.Column('md5', sa.String(32)),
                    sa.Column('adler32', sa.String(8)),
                    sa.Column('bytes', sa.BigInteger),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))

    op.create_table('quarantined_replicas_history',
                    sa.Column('rse_id', GUID()),
                    sa.Column('path', sa.String(1024)),
                    sa.Column('md5', sa.String(32)),
                    sa.Column('adler32', sa.String(8)),
                    sa.Column('bytes', sa.BigInteger),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime),
                    sa.Column('deleted_at', sa.DateTime))

    if context.get_context().dialect.name not in ('sqlite'):
        op.create_primary_key('QURD_REPLICAS_STATE_PK', 'quarantined_replicas', ['rse_id', 'path'])
        op.create_check_constraint('QURD_REPLICAS_CREATED_NN', 'quarantined_replicas', 'created_at is not null')
        op.create_check_constraint('QURD_REPLICAS_UPDATED_NN', 'quarantined_replicas', 'updated_at is not null')
        op.create_foreign_key('QURD_REPLICAS_RSE_ID_FK', 'quarantined_replicas', 'rses', ['rse_id'], ['id'])


def downgrade():
    op.drop_table('quarantined_replicas')
    op.drop_table('quarantined_replicas_history')
