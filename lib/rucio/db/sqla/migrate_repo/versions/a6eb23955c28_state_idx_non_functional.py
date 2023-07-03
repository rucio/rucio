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

""" state idx non functional """

from alembic import context
from alembic.op import create_index, drop_index, execute

# Alembic revision identifiers
revision = 'a6eb23955c28'
down_revision = 'fb28a95fe288'


def upgrade():
    """
    Upgrade the database to this revision
    """

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        execute(f'ALTER INDEX {schema}"RULES_STUCKSTATE_IDX" RENAME TO "RULES_STATE_IDX"')
    elif context.get_context().dialect.name == 'mysql':
        execute(f'ALTER TABLE {schema}rules RENAME INDEX RULES_STUCKSTATE_IDX TO RULES_STATE_IDX')
    elif context.get_context().dialect.name == 'sqlite':
        create_index('RULES_STATE_IDX', 'rules', ['state'])
        drop_index('RULES_STUCKSTATE_IDX', 'rules')


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        execute(f'ALTER INDEX {schema}"RULES_STATE_IDX" RENAME TO "RULES_STUCKSTATE_IDX"')
    elif context.get_context().dialect.name == 'mysql':
        execute(f'ALTER TABLE {schema}rules RENAME INDEX RULES_STATE_IDX TO RULES_STUCKSTATE_IDX')
    elif context.get_context().dialect.name == 'sqlite':
        create_index('RULES_STUCKSTATE_IDX', 'rules', ['state'])
        drop_index('RULES_STATE_IDX', 'rules')
