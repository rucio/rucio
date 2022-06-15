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

''' added column volume to rse_transfer_limits '''

import sqlalchemy as sa

from alembic import context
from alembic.op import (drop_column, add_column)


# Alembic revision identifiers
revision = '2cbee484dcf9'
down_revision = 'cebad904c4dd'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('rse_transfer_limits', sa.Column('volume', sa.BigInteger), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('rse_transfer_limits', 'volume', schema=schema)
