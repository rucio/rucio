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

''' add notification column to rules '''

import sqlalchemy as sa
from alembic import context, op
from alembic.op import add_column, drop_column

from rucio.db.sqla.constants import RuleNotification
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '4207be2fd914'
down_revision = '14ec5aeb64cf'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        add_column('rules', sa.Column('notification', sa.Enum(RuleNotification,
                                                              name='RULES_NOTIFICATION_CHK',
                                                              create_constraint=True,
                                                              values_callable=lambda obj: [e.value for e in obj]),
                                      default=RuleNotification.NO), schema=schema[:-1])
    elif context.get_context().dialect.name == 'postgresql':
        op.execute("CREATE TYPE \"RULES_NOTIFICATION_CHK\" AS ENUM('Y', 'N', 'C', 'P')")
        op.execute("ALTER TABLE %srules ADD COLUMN notification \"RULES_NOTIFICATION_CHK\"" % schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        drop_column('rules', 'notification', schema=schema[:-1])

    elif context.get_context().dialect.name == 'postgresql':
        op.execute('ALTER TABLE %srules DROP CONSTRAINT IF EXISTS "RULES_NOTIFICATION_CHK", ALTER COLUMN notification TYPE CHAR' % schema)
        op.execute('ALTER TABLE %srules DROP COLUMN notification' % schema)
        op.execute('DROP TYPE \"RULES_NOTIFICATION_CHK\"')

    elif context.get_context().dialect.name == 'mysql':
        drop_column('rules', 'notification', schema=schema[:-1])
