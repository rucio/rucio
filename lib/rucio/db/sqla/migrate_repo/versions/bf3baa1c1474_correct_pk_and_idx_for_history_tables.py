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

""" correct PK and IDX for history tables """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    create_primary_key,
    drop_column,
    drop_index,
    is_current_dialect,
    try_drop_constraint,
)
from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = 'bf3baa1c1474'
down_revision = '9eb936a81eb1'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        # CONTENTS_HISTORY
        try_drop_constraint('CONTENTS_HIST_PK', 'contents_history', type_='primary')

        # ARCHIVE_CONTENTS_HISTORY
        try_drop_constraint(constraint_name='ARCH_CONT_HIST_PK', table_name='archive_contents_history', type_='primary')

        # RULES_HIST_RECENT
        try_drop_constraint(constraint_name='RULES_HIST_RECENT_PK', table_name='rules_hist_recent', type_='primary')
        drop_column('rules_hist_recent', 'history_id')

        # RULES_HISTORY
        drop_column('rules_history', 'history_id')


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        # CONTENTS_HISTORY
        create_primary_key('CONTENTS_HIST_PK', 'contents_history', ['scope', 'name', 'child_scope', 'child_name'])

        # ARCHIVE_CONTENTS_HISTORY
        create_primary_key('ARCH_CONT_HIST_PK', 'archive_contents_history', ['scope', 'name', 'child_scope', 'child_name'])
        drop_index('ARCH_CONT_HIST_IDX', 'archive_contents_history')

        # RULES_HIST_RECENT
        add_column('rules_hist_recent', sa.Column('history_id', GUID()))
        create_primary_key('RULES_HIST_RECENT_PK', 'rules_hist_recent', ['history_id'])

        # RULES_HISTORY
        add_column('rules_history', sa.Column('history_id', GUID()))
        create_primary_key('RULES_HIST_LONGTERM_PK', 'rules_history', ['history_id'])

        # MESSAGES_HISTORY
        create_primary_key('MESSAGES_HIST_ID_PK', 'messages_history', ['id'])
