# Copyright 2015-2021 CERN
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
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019-2021

''' extend request state '''

import sqlalchemy as sa
from alembic import context, op
from alembic.op import (add_column, create_check_constraint,
                        drop_constraint, drop_column)

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = 'bb695f45c04'
down_revision = '3082b8cef557'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
        add_column('requests', sa.Column('submitter_id', sa.Integer()), schema=schema[:-1])
        add_column('sources', sa.Column('is_using', sa.Boolean()), schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql':
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
        add_column('requests', sa.Column('submitter_id', sa.Integer()), schema=schema[:-1])
        add_column('sources', sa.Column('is_using', sa.Boolean()), schema=schema[:-1])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        drop_column('requests', 'submitter_id')
        drop_column('sources', 'is_using')

    elif context.get_context().dialect.name == 'postgresql':
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        drop_column('requests', 'submitter_id', schema=schema[:-1])
        drop_column('sources', 'is_using', schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql':
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        drop_column('requests', 'submitter_id', schema=schema[:-1])
        drop_column('sources', 'is_using', schema=schema[:-1])
