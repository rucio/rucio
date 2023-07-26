# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

''' add quarantined_replicas table '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, drop_table)

from rucio.common.schema import get_schema_value
from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '1d1215494e95'
down_revision = '575767d9f89'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('quarantined_replicas',
                     sa.Column('rse_id', GUID()),
                     sa.Column('path', sa.String(1024)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('md5', sa.String(32)),
                     sa.Column('adler32', sa.String(8)),
                     sa.Column('scope', sa.String(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('name', sa.String(get_schema_value('NAME_LENGTH'))),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_table('quarantined_replicas_history',
                     sa.Column('rse_id', GUID()),
                     sa.Column('path', sa.String(1024)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('md5', sa.String(32)),
                     sa.Column('adler32', sa.String(8)),
                     sa.Column('scope', sa.String(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('name', sa.String(get_schema_value('NAME_LENGTH'))),
                     sa.Column('created_at', sa.DateTime),
                     sa.Column('updated_at', sa.DateTime),
                     sa.Column('deleted_at', sa.DateTime, default=datetime.datetime.utcnow))

        create_primary_key('QURD_REPLICAS_STATE_PK', 'quarantined_replicas', ['rse_id', 'path'])
        create_check_constraint('QURD_REPLICAS_CREATED_NN', 'quarantined_replicas', 'created_at is not null')
        create_check_constraint('QURD_REPLICAS_UPDATED_NN', 'quarantined_replicas', 'updated_at is not null')
        create_foreign_key('QURD_REPLICAS_RSE_ID_FK', 'quarantined_replicas', 'rses', ['rse_id'], ['id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('quarantined_replicas')
        drop_table('quarantined_replicas_history')
