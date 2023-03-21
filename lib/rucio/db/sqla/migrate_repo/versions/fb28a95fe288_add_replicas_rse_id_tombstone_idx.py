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

''' add_replicas_rse_id_tombstone_idx '''

from alembic.op import create_index, drop_index

# Alembic revision identifiers
revision = 'fb28a95fe288'
down_revision = '140fef722e91'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    create_index('REPLICAS_RSE_ID_TOMBSTONE_IDX', 'replicas', ['rse_id', 'tombstone'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    drop_index('REPLICAS_RSE_ID_TOMBSTONE_IDX', 'replicas')
