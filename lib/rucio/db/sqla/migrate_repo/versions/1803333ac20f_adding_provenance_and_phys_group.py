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

""" adding provenance and phys_group """

import sqlalchemy as sa

from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    is_current_dialect,
)

# Alembic revision identifiers
revision = '1803333ac20f'
down_revision = '4c3a4acfe006'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('dids', sa.Column('provenance', sa.String(2)))
        add_column('dids', sa.Column('phys_group', sa.String(25)))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_column('dids', 'provenance')
        drop_column('dids', 'phys_group')
