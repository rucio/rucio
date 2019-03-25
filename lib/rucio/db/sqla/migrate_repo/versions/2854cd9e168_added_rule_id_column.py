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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' added_rule_id_column '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column

from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '2854cd9e168'
down_revision = '35ef10d1e11b'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('rule_id', GUID()), schema=schema)
        add_column('requests_history', sa.Column('rule_id', GUID()), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'rule_id', schema=schema)
        drop_column('requests_history', 'rule_id', schema=schema)
