# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""Create collection replica table

Revision ID: 45378a1e76a8
Revises: a93e4e47bda
Create Date: 2015-03-03 13:57:31.258138

"""

from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index,
                        drop_constraint, drop_index, drop_table)
from alembic import context
import sqlalchemy as sa

from rucio.db.sqla.constants import ReplicaState, DIDType
from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '45378a1e76a8'
down_revision = 'a93e4e47bda'


def upgrade():
    '''
    upgrade method
    '''
    create_table('collection_replicas',
                 sa.Column('scope', sa.String(25)),
                 sa.Column('name', sa.String(255)),
                 sa.Column('did_type', DIDType.db_type(name='COLLECTION_REPLICAS_TYPE_CHK')),
                 sa.Column('rse_id', GUID()),
                 sa.Column('bytes', sa.BigInteger),
                 sa.Column('length', sa.BigInteger),
                 sa.Column('state', ReplicaState.db_type(name='COLLECTION_REPLICAS_STATE_CHK'), default=ReplicaState.UNAVAILABLE),
                 sa.Column('accessed_at', sa.DateTime),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('COLLECTION_REPLICAS_PK', 'collection_replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('COLLECTION_REPLICAS_LFN_FK', 'collection_replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('COLLECTION_REPLICAS_RSE_ID_FK', 'collection_replicas', 'rses', ['rse_id'], ['id'])
        create_check_constraint('COLLECTION_REPLICAS_SIZE_NN', 'collection_replicas', 'bytes IS NOT NULL')
        create_check_constraint('COLLECTION_REPLICAS_STATE_NN', 'collection_replicas', 'state IS NOT NULL')
        create_index('COLLECTION_REPLICAS_RSE_ID_IDX', 'collection_replicas', ['rse_id'])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name == 'postgresql':
        drop_constraint('COLLECTION_REPLICAS_PK', 'collection_replicas', type_='primary')
        drop_constraint('COLLECTION_REPLICAS_TYPE_CHK', 'collection_replicas')
        drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        drop_constraint('COLLECTION_REPLICAS_LFN_FK', 'collection_replicas')
        drop_constraint('COLLECTION_REPLICAS_RSE_ID_FK', 'collection_replicas')
        drop_constraint('COLLECTION_REPLICAS_SIZE_NN', 'collection_replicas')
        drop_constraint('COLLECTION_REPLICAS_STATE_NN', 'collection_replicas')
        drop_index('COLLECTION_REPLICAS_RSE_ID_IDX', 'collection_replicas')
    drop_table('collection_replicas')
