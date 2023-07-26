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

''' add didtype_chck to requests '''

import sqlalchemy as sa
from alembic import context, op
from alembic.op import add_column, drop_column

from rucio.db.sqla.constants import DIDType

# Alembic revision identifiers
revision = '1a29d6a9504c'
down_revision = '436827b13f82'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''  # pylint: disable=no-member

    if context.get_context().dialect.name in ['oracle', 'mysql']:  # pylint: disable=no-member
        add_column('requests', sa.Column('did_type',
                                         sa.Enum(DIDType,
                                                 name='REQUESTS_DIDTYPE_CHK',
                                                 create_constraint=True,
                                                 values_callable=lambda obj: [e.value for e in obj]),
                                         default=DIDType.FILE), schema=schema[:-1])
        # we don't want checks on the history table, fake the DID type
        add_column('requests_history', sa.Column('did_type', sa.String(1)), schema=schema[:-1])

    elif context.get_context().dialect.name == 'postgresql':  # pylint: disable=no-member
        op.execute("ALTER TABLE %srequests ADD COLUMN did_type \"REQUESTS_DIDTYPE_CHK\"" % schema)  # pylint: disable=no-member
        # we don't want checks on the history table, fake the DID type
        add_column('requests_history', sa.Column('did_type', sa.String(1)), schema=schema[:-1])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''  # pylint: disable=no-member

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:  # pylint: disable=no-member
        drop_column('requests', 'did_type', schema=schema)
        drop_column('requests_history', 'did_type', schema=schema)
