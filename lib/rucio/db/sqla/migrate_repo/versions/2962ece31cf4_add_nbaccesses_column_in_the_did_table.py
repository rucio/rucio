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

""" add access_cnt column in the DID table """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    is_current_dialect,
)

# Alembic revision identifiers
revision = '2962ece31cf4'
down_revision = '94a5961ddbf2'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('dids', sa.Column('access_cnt', sa.Integer))
        add_column('deleted_dids', sa.Column('access_cnt', sa.Integer))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_column('dids', 'access_cnt')
        drop_column('deleted_dids', 'access_cnt')
