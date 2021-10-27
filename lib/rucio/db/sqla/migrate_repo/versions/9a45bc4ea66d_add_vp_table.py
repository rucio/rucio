# Copyright 2013-2021 CERN
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
#
# Authors:
# - Ilija Vukotic <ivukotic@uchicago.edu>, 2021

''' add VP table '''

import sqlalchemy as sa

from alembic import context
from alembic.op import create_primary_key, create_table, create_foreign_key, drop_table, create_index

from rucio.db.sqla.types import JSON

# Alembic revision identifiers
revision = '9a45bc4ea66d'
down_revision = '739064d31565'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('did_virtual_placements',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('placements', JSON()),
                     sa.Column('created_at', sa.DateTime),
                     sa.Column('updated_at', sa.DateTime)
                     )

        create_primary_key('DID_VP_PK', 'did_virtual_placements', ['scope', 'name'])
        create_foreign_key('DID_VP_FK', 'did_virtual_placements', 'dids',
                           ['scope', 'name'], ['scope', 'name'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('did_virtual_placements')
