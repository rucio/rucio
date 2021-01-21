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
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Robert Illingworth <illingwo@fnal.gov>, 2019

''' asynchronous rules and rule approval '''

import sqlalchemy as sa

from alembic import context, op
from alembic.op import (add_column, create_check_constraint,
                        drop_constraint, drop_column)


# Alembic revision identifiers
revision = '1d96f484df21'
down_revision = '3d9813fab443'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False))
        drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O', 'W', 'I')")

    elif context.get_context().dialect.name == 'postgresql':
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False), schema=schema[:-1])
        op.execute('ALTER TABLE ' + schema + 'rules DROP CONSTRAINT IF EXISTS "RULES_STATE_CHK", ALTER COLUMN state TYPE CHAR')
        op.execute("DROP TYPE \"RULES_STATE_CHK\"")
        op.execute("CREATE TYPE \"RULES_STATE_CHK\" AS ENUM('S', 'R', 'U', 'O', 'W', 'I')")
        op.execute("ALTER TABLE %srules ALTER COLUMN state TYPE \"RULES_STATE_CHK\" USING state::\"RULES_STATE_CHK\"" % schema)

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False), schema=schema[:-1])
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O', 'W', 'I')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        add_column('rules', sa.Column('ignore_account_limit', sa.Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False), schema=schema[:-1])
        op.execute('ALTER TABLE ' + schema + 'rules DROP CHECK RULES_STATE_CHK')  # pylint: disable=no-member
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O', 'W', 'I')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        drop_column('rules', 'ignore_account_limit')
        drop_constraint('RULES_STATE_CHK', 'rules')
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O')")

    elif context.get_context().dialect.name == 'postgresql':
        drop_column('rules', 'ignore_account_limit', schema=schema[:-1])
        op.execute('ALTER TABLE ' + schema + 'rules DROP CONSTRAINT IF EXISTS "RULES_STATE_CHK", ALTER COLUMN state TYPE CHAR')
        op.execute("DROP TYPE \"RULES_STATE_CHK\"")
        op.execute("CREATE TYPE \"RULES_STATE_CHK\" AS ENUM('S', 'R', 'U', 'O')")
        op.execute("ALTER TABLE %srules ALTER COLUMN state TYPE \"RULES_STATE_CHK\" USING state::\"RULES_STATE_CHK\"" % schema)

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:
        drop_column('rules', 'ignore_account_limit', schema=schema[:-1])
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:
        drop_column('rules', 'ignore_account_limit', schema=schema[:-1])
        create_check_constraint('RULES_STATE_CHK', 'rules', "state IN ('S', 'R', 'U', 'O')")
