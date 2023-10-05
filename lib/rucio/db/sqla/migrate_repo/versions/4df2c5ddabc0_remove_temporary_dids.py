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

''' remove temporary dids '''

import sqlalchemy as sa
from alembic import context
from alembic.op import create_index, create_primary_key, create_table, drop_table

from rucio.common.schema import get_schema_value
from rucio.db.sqla.types import InternalScopeString, GUID

# Alembic revision identifiers
revision = '4df2c5ddabc0'
down_revision = '27e3a68927fb'


def upgrade():
    '''Upgrade the database to this revision'''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('tmp_dids')


def downgrade():
    '''Downgrade the database to the previous revision'''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('tmp_dids',
                     sa.Column('scope', InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('name', sa.String(get_schema_value('NAME_LENGTH'))),
                     sa.Column('rse_id', GUID()),
                     sa.Column('path', sa.String(1024)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('md5', sa.String(32)),
                     sa.Column('adler32', sa.String(8)),
                     sa.Column('expired_at', sa.DateTime),
                     sa.Column('guid', GUID()),
                     sa.Column('events', sa.BigInteger),
                     sa.Column('task_id', sa.Integer),
                     sa.Column('panda_id', sa.Integer),
                     sa.Column('parent_scope', InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('parent_name', sa.String(get_schema_value('NAME_LENGTH'))),
                     sa.Column('offset', sa.BigInteger))
        create_primary_key('TMP_DIDS_PK', 'tmp_dids', ['scope', 'name'])
        create_index('TMP_DIDS_EXPIRED_AT_IDX', 'tmp_dids', ['expired_at'])
