# -*- coding: utf-8 -*-
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

''' add index to quarantined replicas '''

from alembic import context
from alembic.op import (create_index, drop_index)


# revision identifiers, used by Alembic.
revision = 'b818052fa670'
down_revision = '2962ece31cf4'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_index('QUARANTINED_REPLICAS_PATH_IDX', 'quarantined_replicas', ['path', 'rse_id'], unique=True)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_index('QUARANTINED_REPLICAS_PATH_IDX', 'quarantined_replicas')
