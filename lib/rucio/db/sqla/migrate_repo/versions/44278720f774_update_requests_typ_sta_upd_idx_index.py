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

''' update REQUESTS_TYP_STA_UPD_IDX index '''

from alembic import context
from alembic.op import create_index, drop_index


# Alembic revision identifiers
revision = '44278720f774'
down_revision = '40ad39ce3160'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_index('REQUESTS_TYP_STA_UPD_IDX', 'requests')
        create_index('REQUESTS_TYP_STA_UPD_IDX', 'requests', ['request_type', 'state', 'activity'])
        create_index('REQUESTS_TYP_STA_UPD_IDX_OLD', 'requests', ['request_type', 'state', 'updated_at'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_index('REQUESTS_TYP_STA_UPD_IDX', 'requests')
        drop_index('REQUESTS_TYP_STA_UPD_IDX_OLD', 'requests')
        create_index('REQUESTS_TYP_STA_UPD_IDX', 'requests', ['request_type', 'state', 'updated_at'])
