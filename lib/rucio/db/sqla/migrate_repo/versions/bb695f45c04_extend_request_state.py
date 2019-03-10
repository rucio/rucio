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
# - Wen Guan <wen.guan@cern.ch>, 2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' extend request state '''

import sqlalchemy as sa

from alembic import context
from alembic.op import (add_column, create_check_constraint,
                        drop_constraint, drop_column)


# Alembic revision identifiers
revision = 'bb695f45c04'
down_revision = '3082b8cef557'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('requests', sa.Column('submitter_id', sa.Integer()), schema=schema)
        add_column('sources', sa.Column('is_using', sa.Boolean()), schema=schema)

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
        add_column('requests', sa.Column('submitter_id', sa.Integer()))
        add_column('sources', sa.Column('is_using', sa.Boolean()))


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name == 'oracle':
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        drop_column('requests', 'submitter_id')
        drop_column('sources', 'is_using')

    elif context.get_context().dialect.name == 'postgresql':
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('requests', 'submitter_id', schema=schema)
        drop_column('sources', 'is_using', schema=schema)

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        drop_column('requests', 'submitter_id')
        drop_column('sources', 'is_using')
