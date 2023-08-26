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

''' create sources table '''

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '22d887e4ec0a'
down_revision = '1a80adff031a'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('sources',
                     sa.Column('request_id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('dest_rse_id', GUID()),
                     sa.Column('url', sa.String(2048)),
                     sa.Column('ranking', sa.Integer),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('SOURCES_PK', 'sources', ['request_id', 'rse_id', 'scope', 'name'])
        create_foreign_key('SOURCES_REQ_ID_FK', 'sources', 'requests', ['request_id'], ['id'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])
        create_foreign_key('SOURCES_RSES_FK', 'sources', 'rses', ['rse_id'], ['id'])
        create_foreign_key('SOURCES_DST_RSES_FK', 'sources', 'rses', ['dest_rse_id'], ['id'])
        create_check_constraint('SOURCES_CREATED_NN', 'sources', 'created_at is not null')
        create_check_constraint('SOURCES_UPDATED_NN', 'sources', 'updated_at is not null')
        create_index('SOURCES_SRC_DST_IDX', 'sources', ['rse_id', 'dest_rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('sources')
