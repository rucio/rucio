# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2019
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' create collection replica table '''

import datetime

import sqlalchemy as sa

from alembic import context, op
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table,
                        drop_constraint)

from rucio.db.sqla.constants import ReplicaState, DIDType
from rucio.db.sqla.types import GUID


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
                     sa.Column('did_type', DIDType.db_type()),
                     sa.Column('rse_id', GUID()),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('length', sa.BigInteger),
                     sa.Column('state', ReplicaState.db_type(), default=ReplicaState.UNAVAILABLE),
                     sa.Column('accessed_at', sa.DateTime),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('COLLECTION_REPLICAS_PK', 'collection_replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('COLLECTION_REPLICAS_LFN_FK', 'collection_replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('COLLECTION_REPLICAS_RSE_ID_FK', 'collection_replicas', 'rses', ['rse_id'], ['id'])
        create_check_constraint('COLLECTION_REPLICAS_SIZE_NN', 'collection_replicas', 'bytes IS NOT NULL')
        create_check_constraint('COLLECTION_REPLICAS_STATE_NN', 'collection_replicas', 'state IS NOT NULL')
        create_check_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas', "state in ('A', 'U', 'C', 'B', 'D', 'S')")
        create_index('COLLECTION_REPLICAS_RSE_ID_IDX', 'collection_replicas', ['rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name == 'oracle':
        drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas', type_='check')
        drop_table('collection_replicas')

    elif context.get_context().dialect.name == 'postgresql':
        schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
        op.execute('ALTER TABLE ' + schema + 'collection_replicas ALTER COLUMN state TYPE CHAR')  # pylint: disable=no-member
        drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas', type_='check')
        drop_table('collection_replicas')

    elif context.get_context().dialect.name == 'mysql':
        drop_table('collection_replicas')
