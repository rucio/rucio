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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2019
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017

''' add didtype_chck to requests '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

from rucio.db.sqla.constants import DIDType

# Alembic revision identifiers
revision = '1a29d6a9504c'
down_revision = '436827b13f82'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('did_type',
                                         DIDType.db_type(name='REQUESTS_DIDTYPE_CHK'),
                                         default=DIDType.FILE), schema=schema)
        # we don't want checks on the history table, fake the DID type
        add_column('requests_history', sa.Column('did_type', sa.String(1)), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'did_type', schema=schema)
        drop_column('requests_history', 'did_type', schema=schema)
