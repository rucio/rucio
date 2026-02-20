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

""" added source history table """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    create_table,
    drop_column,
    drop_table,
    is_current_dialect,
)
from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '575767d9f89'
down_revision = '379a19b5332d'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        create_table('sources_history',
                     sa.Column('request_id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('dest_rse_id', GUID()),
                     sa.Column('url', sa.String(2048)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('ranking', sa.Integer()),
                     sa.Column('is_using', sa.Boolean(), default=False))
        add_column('requests', sa.Column('estimated_at', sa.DateTime))
        add_column('requests_history', sa.Column('estimated_at', sa.DateTime))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_column('requests', 'estimated_at')
        drop_column('requests_history', 'estimated_at')
        drop_table('sources_history')
