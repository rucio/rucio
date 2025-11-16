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

""" add eol_at in rules """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    is_current_dialect,
)

# Alembic revision identifiers
revision = '0437a40dbfd1'
down_revision = 'a5f6f6e928a7'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('rules', sa.Column('eol_at', sa.DateTime))
        add_column('rules_hist_recent', sa.Column('eol_at', sa.DateTime))
        add_column('rules_history', sa.Column('eol_at', sa.DateTime))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_column('rules', 'eol_at')
        drop_column('rules_hist_recent', 'eol_at')
        drop_column('rules_history', 'eol_at')
