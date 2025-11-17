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

""" added child_rule_id column """

import sqlalchemy as sa
from alembic.op import create_foreign_key

from rucio.db.sqla.migrate_repo import (
    add_column,
    create_index,
    drop_column,
    is_current_dialect,
    try_drop_constraint,
    try_drop_index,
)
from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '5f139f77382a'
down_revision = '1d1215494e95'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('rules', sa.Column('child_rule_id', GUID()))
        add_column('rules_hist_recent', sa.Column('child_rule_id', GUID()))
        add_column('rules_history', sa.Column('child_rule_id', GUID()))

        create_foreign_key('RULES_CHILD_RULE_ID_FK', 'rules', 'rules', ['child_rule_id'], ['id'])
        create_index('RULES_CHILD_RULE_ID_IDX', 'rules', ['child_rule_id'])


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        try_drop_constraint('RULES_CHILD_RULE_ID_FK', 'rules')
        try_drop_index('RULES_CHILD_RULE_ID_IDX', 'rules')

        drop_column('rules', 'child_rule_id')
        drop_column('rules_hist_recent', 'child_rule_id')
        drop_column('rules_history', 'child_rule_id')
