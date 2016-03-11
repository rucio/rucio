# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

"""remove unique constraint on requests

Revision ID: 25821a8a45a3
Revises: 1803333ac20f
Create Date: 2015-01-09 14:48:20.833140

"""

from alembic import context, op

# revision identifiers, used by Alembic.
revision = '25821a8a45a3'
down_revision = '1803333ac20f'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        # mysql has to remove FK constraint to drop IDX
        op.drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')
        op.drop_constraint('REQUESTS_DID_FK', 'requests', type_='foreignkey')
        op.drop_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', type_='unique')
        op.create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        op.create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        op.create_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        # mysql has to remove FK constraint to drop IDX
        op.drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')
        op.drop_constraint('REQUESTS_DID_FK', 'requests', type_='foreignkey')
        op.drop_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests')
        op.create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        op.create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        op.create_unique_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])
