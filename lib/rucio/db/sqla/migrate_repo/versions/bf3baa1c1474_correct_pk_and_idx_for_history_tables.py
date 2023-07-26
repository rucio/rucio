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

''' correct PK and IDX for history tables '''

import sqlalchemy as sa
from alembic import context
from alembic.op import (create_primary_key, drop_constraint,
                        drop_index, drop_column, add_column)

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = 'bf3baa1c1474'
down_revision = '9eb936a81eb1'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        # CONTENTS_HISTORY
        drop_constraint('CONTENTS_HIST_PK', 'contents_history', type_='primary')

        # ARCHIVE_CONTENTS_HISTORY
        drop_constraint(constraint_name='ARCH_CONT_HIST_PK', table_name='archive_contents_history', type_='primary')

        # RULES_HIST_RECENT
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_constraint(constraint_name='RULES_HIST_RECENT_PK', table_name='rules_hist_recent', type_='primary')
        drop_column('rules_hist_recent', 'history_id', schema=schema)

        # RULES_HISTORY
        drop_column('rules_history', 'history_id', schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        # CONTENTS_HISTORY
        create_primary_key('CONTENTS_HIST_PK', 'contents_history', ['scope', 'name', 'child_scope', 'child_name'])

        # ARCHIVE_CONTENTS_HISTORY
        create_primary_key('ARCH_CONT_HIST_PK', 'archive_contents_history', ['scope', 'name', 'child_scope', 'child_name'])
        drop_index('ARCH_CONT_HIST_IDX', 'archive_contents_history')

        # RULES_HIST_RECENT
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('rules_hist_recent', sa.Column('history_id', GUID()), schema=schema)
        create_primary_key('RULES_HIST_RECENT_PK', 'rules_hist_recent', ['history_id'])

        # RULES_HISTORY
        add_column('rules_history', sa.Column('history_id', GUID()), schema=schema)
        create_primary_key('RULES_HIST_LONGTERM_PK', 'rules_history', ['history_id'])

        # MESSAGES_HISTORY
        create_primary_key('MESSAGES_HIST_ID_PK', 'messages_history', ['id'])
