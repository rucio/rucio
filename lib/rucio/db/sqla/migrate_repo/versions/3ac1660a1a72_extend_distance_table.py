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

""" extend distance table """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    is_current_dialect,
)

# Alembic revision identifiers
revision = '3ac1660a1a72'
down_revision = '5673b4b6e843'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('distances', sa.Column('packet_loss', sa.Integer))
        add_column('distances', sa.Column('latency', sa.Integer))
        add_column('distances', sa.Column('mbps_file', sa.Integer))
        add_column('distances', sa.Column('mbps_link', sa.Integer))
        add_column('distances', sa.Column('queued_total', sa.Integer))
        add_column('distances', sa.Column('done_1h', sa.Integer))
        add_column('distances', sa.Column('done_6h', sa.Integer))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_column('distances', 'packet_loss')
        drop_column('distances', 'latency')
        drop_column('distances', 'mbps_file')
        drop_column('distances', 'mbps_link')
        drop_column('distances', 'queued_total')
        drop_column('distances', 'done_1h')
        drop_column('distances', 'done_6h')
