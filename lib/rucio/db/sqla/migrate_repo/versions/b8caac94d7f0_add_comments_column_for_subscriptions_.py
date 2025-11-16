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

""" add comments column for subscriptions_history """

import sqlalchemy as sa
from alembic.op import drop_column

from rucio.db.sqla.migrate_repo import add_column, get_effective_schema, is_current_dialect

# Alembic revision identifiers
revision = 'b8caac94d7f0'
down_revision = '8523998e2e76'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('subscriptions_history', sa.Column('comments', sa.String(4000)))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        schema = get_effective_schema()
        drop_column('subscriptions_history', 'comments', schema=schema)
