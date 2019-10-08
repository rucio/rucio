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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' add notification column to rules '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_constraint, drop_column

from rucio.db.sqla.constants import RuleNotification


# Alembic revision identifiers
revision = '4207be2fd914'
down_revision = '14ec5aeb64cf'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('rules', sa.Column('notification', RuleNotification.db_type(name='RULES_NOTIFICATION_CHK'),
                                      default=RuleNotification.NO), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('RULES_NOTIFICATION_CHK', 'rules', type_='check')
        drop_column('rules', 'notification', schema=schema)

    elif context.get_context().dialect.name == 'mysql':
        drop_column('rules', 'notification', schema=schema)
