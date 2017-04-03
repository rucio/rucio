# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""add request_type to requests idx

Revision ID: 156fb5b5a14
Revises: 1a29d6a9504c
Create Date: 2014-10-13 14:12:05.081808

"""
from alembic import context
from alembic.op import (create_foreign_key, create_unique_constraint, create_index,
                        drop_constraint, drop_index)

# revision identifiers, used by Alembic.
revision = '156fb5b5a14'
down_revision = '1a29d6a9504c'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        # mysql has to remove FK constraint to drop IDX
        drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')
        drop_constraint('REQUESTS_DID_FK', 'requests', type_='foreignkey')
        drop_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests')
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_unique_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        # mysql has to remove FK constraint to drop IDX
        drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')
        drop_constraint('REQUESTS_DID_FK', 'requests', type_='foreignkey')
        drop_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', type_='unique')
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])
