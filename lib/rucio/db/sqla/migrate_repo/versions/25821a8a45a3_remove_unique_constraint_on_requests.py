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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015-2019
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017

''' remove unique constraint on requests '''

from alembic import context
from alembic.op import (create_foreign_key, create_index, drop_index,
                        drop_constraint, create_unique_constraint)


# Alembic revision identifiers
revision = '25821a8a45a3'
down_revision = '1803333ac20f'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')
        drop_constraint('REQUESTS_DID_FK', 'requests', type_='foreignkey')
        drop_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', type_='unique')
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])


def downgrade():

    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')
        drop_constraint('REQUESTS_DID_FK', 'requests', type_='foreignkey')
        drop_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests')
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_unique_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])
