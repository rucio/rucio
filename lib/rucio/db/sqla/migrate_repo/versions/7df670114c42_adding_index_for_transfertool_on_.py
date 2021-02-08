# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Matt Snyder <msnyder@bnl.gov>, 2021

''' adding index for transfertool on requests table '''

from alembic import context
from alembic.op import create_index, drop_index

# Alembic revision identifiers
revision = '7df670114c42'
down_revision = 'f85a2962b021'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_index('REQUESTS_TYP_STA_TRANS_ACT_IDX', 'requests', ['request_type', 'state', 'transfertool'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_index('REQUESTS_TYP_STA_TRANS_ACT_IDX', 'requests')
