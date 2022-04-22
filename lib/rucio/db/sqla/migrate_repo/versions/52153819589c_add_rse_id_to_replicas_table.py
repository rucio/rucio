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

''' add_rse_id_to_replicas_table '''


from alembic import context
from alembic.op import create_foreign_key, create_index, drop_constraint, drop_index


# Alembic revision identifiers
revision = '52153819589c'
down_revision = '30fa38b6434e'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    create_index('REPLICAS_RSE_ID_IDX', 'replicas', ['rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['mysql']:
        drop_constraint('REPLICAS_RSE_ID_FK', 'replicas', type_='foreignkey')
    drop_index('REPLICAS_RSE_ID_IDX', 'replicas')
    if context.get_context().dialect.name in ['mysql']:
        create_foreign_key('REPLICAS_RSE_ID_FK', 'replicas', 'rses', ['rse_id'], ['id'])
