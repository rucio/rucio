# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019-2020

''' create collection replica table '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)

from rucio.db.sqla.constants import ReplicaState, DIDType
from rucio.db.sqla.types import GUID
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '45378a1e76a8'
down_revision = 'a93e4e47bda'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('collection_replicas',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('did_type', sa.Enum(DIDType, name='COLLECTION_REPLICAS_TYPE_CHK', values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('rse_id', GUID()),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('length', sa.BigInteger),
                     sa.Column('state', sa.Enum(ReplicaState, name='COLLECTION_REPLICAS_STATE_CHK', values_callable=lambda obj: [e.value for e in obj]), default=ReplicaState.UNAVAILABLE),
                     sa.Column('accessed_at', sa.DateTime),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('COLLECTION_REPLICAS_PK', 'collection_replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('COLLECTION_REPLICAS_LFN_FK', 'collection_replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('COLLECTION_REPLICAS_RSE_ID_FK', 'collection_replicas', 'rses', ['rse_id'], ['id'])
        create_check_constraint('COLLECTION_REPLICAS_SIZE_NN', 'collection_replicas', 'bytes IS NOT NULL')
        create_check_constraint('COLLECTION_REPLICAS_STATE_NN', 'collection_replicas', 'state IS NOT NULL')
        create_index('COLLECTION_REPLICAS_RSE_ID_IDX', 'collection_replicas', ['rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas')
        drop_table('collection_replicas')

    elif context.get_context().dialect.name == 'postgresql':
        drop_table('collection_replicas')

    elif context.get_context().dialect.name == 'mysql':
        drop_table('collection_replicas')
