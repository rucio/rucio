# Copyright 2016-2021 CERN
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
# - Wen Guan <wguan.icedew@gmail.com>, 2016
# - Vincent Garonne <vgaronne@gmail.com>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019-2021
# - Robert Illingworth <illingwo@fnal.gov>, 2019

''' add mismatch scheme state to requests '''

from alembic import context, op
from alembic.op import create_check_constraint

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '21d6b9dc9961'
down_revision = '5f139f77382a'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M')")

    elif context.get_context().dialect.name == 'mysql':
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('REQUESTS_STATE_CHK', 'requests')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")

    elif context.get_context().dialect.name == 'postgresql':
        op.execute('ALTER TABLE ' + schema + 'requests DROP CONSTRAINT IF EXISTS "REQUESTS_STATE_CHK", ALTER COLUMN state TYPE CHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")
