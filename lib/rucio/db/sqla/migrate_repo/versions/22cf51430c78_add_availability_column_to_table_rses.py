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

''' add availability column to table RSEs '''

import sqlalchemy as sa
from alembic.op import add_column, drop_column

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect

# Alembic revision identifiers
revision = '22cf51430c78'
down_revision = '49a21b4d4357'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        schema = get_effective_schema()
        add_column('rses', sa.Column('availability', sa.Integer, server_default='7'), schema=schema)


def downgrade():
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        schema = get_effective_schema()
        drop_column('rses', 'availability', schema=schema)
