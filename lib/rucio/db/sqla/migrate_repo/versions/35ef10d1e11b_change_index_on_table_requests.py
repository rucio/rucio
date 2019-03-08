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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' change index on table requests '''

from alembic import context
from alembic.op import create_index, drop_index


# Alembic revision identifiers
revision = '35ef10d1e11b'
down_revision = '3152492b110b'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        create_index('REQUESTS_TYP_STA_UPD_IDX', 'requests', ["request_type", "state", "updated_at"])
        drop_index('REQUESTS_TYP_STA_CRE_IDX', 'requests')

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        create_index('REQUESTS_TYP_STA_CRE_IDX', 'requests', ["request_type", "state", "created_at"])
        drop_index('REQUESTS_TYP_STA_UPD_IDX', 'requests')

    elif context.get_context().dialect.name == 'postgresql':
        pass
