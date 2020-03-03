# Copyright 2015-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Vincent Garonne <vgaronne@gmail.com>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' extend waiting request state '''

from alembic import context, op
from alembic.op import create_check_constraint, drop_constraint


# Alembic revision identifiers
revision = '3c9df354071b'
down_revision = '2edee4a83846'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U','W')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U','W')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U','W')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        op.execute('ALTER TABLE ' + schema + 'requests DROP CHECK REQUESTS_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='REQUESTS_STATE_CHK', table_name='requests',
                                condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
