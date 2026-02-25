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

""" added_columns_rse_transfer_limits """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    is_current_dialect,
)

# Alembic revision identifiers
revision = '810a41685bc1'
down_revision = '7541902bf173'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'postgresql', 'mysql'):
        add_column('rse_transfer_limits', sa.Column('deadline', sa.BigInteger))
        add_column('rse_transfer_limits', sa.Column('strategy', sa.String(25)))
        add_column('rse_transfer_limits', sa.Column('direction', sa.String(25)))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'postgresql', 'mysql'):
        drop_column('rse_transfer_limits', 'deadline')
        drop_column('rse_transfer_limits', 'strategy')
        drop_column('rse_transfer_limits', 'direction')
