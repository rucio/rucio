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

''' adding did_meta table '''

import sqlalchemy as sa

from alembic import context
from alembic.op import create_primary_key, create_table, create_foreign_key, drop_table

from rucio.db.sqla.types import JSON


# Alembic revision identifiers
revision = '688ef1840840'
down_revision = 'b818052fa670'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('did_meta',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('meta', JSON()))

        create_primary_key('DID_META_PK', 'did_meta', ['scope', 'name'])
        create_foreign_key('DID_META_FK', 'did_meta', 'dids',
                           ['scope', 'name'], ['scope', 'name'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('did_meta')
