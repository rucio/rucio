# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' added bytes, length, accessed_at columns '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column


# Alembic revision identifiers
revision = '4a7182d9578b'
down_revision = 'c129ccdb2d5'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        add_column('dataset_locks', sa.Column('length', sa.BigInteger()))
        add_column('dataset_locks', sa.Column('bytes', sa.BigInteger()))
        add_column('dataset_locks', sa.Column('accessed_at', sa.DateTime()))
        add_column('dids', sa.Column('accessed_at', sa.DateTime()))

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_column('dataset_locks', 'length')
        drop_column('dataset_locks', 'bytes')
        drop_column('dataset_locks', 'accessed_at')
        drop_column('dids', 'accessed_at')

    elif context.get_context().dialect.name == 'postgresql':
        pass
