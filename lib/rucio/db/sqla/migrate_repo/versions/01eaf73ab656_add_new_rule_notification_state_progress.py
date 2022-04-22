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

''' add new rule notification state progress '''

from alembic import context, op
from alembic.op import create_check_constraint

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '01eaf73ab656'
down_revision = '90f47792bb76'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        create_check_constraint(constraint_name='RULES_NOTIFICATION_CHK', table_name='rules',
                                condition="notification in ('Y', 'N', 'C', 'P')")

    elif context.get_context().dialect.name == 'postgresql':
        op.execute('ALTER TABLE ' + schema + 'rules DROP CONSTRAINT IF EXISTS "RULES_NOTIFICATION_CHK", ALTER COLUMN notification TYPE CHAR')
        op.execute('DROP TYPE \"RULES_NOTIFICATION_CHK\"')
        op.execute("CREATE TYPE \"RULES_NOTIFICATION_CHK\" AS ENUM('Y', 'N', 'C', 'P')")
        op.execute("ALTER TABLE %srules ALTER COLUMN notification TYPE \"RULES_NOTIFICATION_CHK\" USING notification::\"RULES_NOTIFICATION_CHK\"" % schema)

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='RULES_NOTIFICATION_CHK', table_name='rules',
                                condition="notification in ('Y', 'N', 'C', 'P')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        create_check_constraint(constraint_name='RULES_NOTIFICATION_CHK', table_name='rules',
                                condition="notification in ('Y', 'N', 'C')")

    elif context.get_context().dialect.name == 'postgresql':
        op.execute('ALTER TABLE ' + schema + 'rules DROP CONSTRAINT IF EXISTS "RULES_NOTIFICATION_CHK", ALTER COLUMN notification TYPE CHAR')
        op.execute('DROP TYPE "RULES_NOTIFICATION_CHK"')
        op.execute("CREATE TYPE \"RULES_NOTIFICATION_CHK\" AS ENUM('Y', 'N', 'C')")
        op.execute("ALTER TABLE %srules ALTER COLUMN notification TYPE \"RULES_NOTIFICATION_CHK\" USING notification::\"RULES_NOTIFICATION_CHK\"" % schema)

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='RULES_NOTIFICATION_CHK', table_name='rules',
                                condition="notification in ('Y', 'N', 'C')")
