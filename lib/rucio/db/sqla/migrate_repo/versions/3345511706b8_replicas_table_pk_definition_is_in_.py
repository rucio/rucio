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
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' replicas table PK definition is in wrong order '''

from alembic import context
from alembic.op import create_primary_key, drop_constraint, create_foreign_key, drop_index


# revision identifiers used by alembic
revision = '3345511706b8'
down_revision = '01eaf73ab656'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('SOURCES_REPLICA_FK', 'sources', type_='foreignkey')
        drop_constraint('REPLICAS_PK', 'replicas', type_='primary')
        create_primary_key('REPLICAS_PK', 'replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])

    elif context.get_context().dialect.name == 'mysql':
        drop_constraint('SOURCES_REPLICA_FK', 'sources', type_='foreignkey')
        # The constraint has an internal index which is not automatically dropped,
        # we have to do that manually
        drop_index('SOURCES_REPLICA_FK', 'sources')
        drop_constraint(constraint_name='REPLICAS_LFN_FK', table_name='replicas', type_='foreignkey')
        drop_constraint(constraint_name='REPLICAS_RSE_ID_FK', table_name='replicas', type_='foreignkey')
        drop_constraint('REPLICAS_PK', 'replicas', type_='primary')
        create_foreign_key('REPLICAS_LFN_FK', 'replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('REPLICAS_RSE_ID_FK', 'replicas', 'rses', ['rse_id'], ['id'])
        create_primary_key('REPLICAS_PK', 'replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint(constraint_name='SOURCES_REPLICA_FK', table_name='sources', type_='foreignkey')
        drop_constraint(constraint_name='REPLICAS_PK', table_name='replicas', type_='primary')
        create_primary_key('REPLICAS_PK', 'replicas', ['rse_id', 'scope', 'name'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['rse_id', 'scope', 'name'], ['rse_id', 'scope', 'name'])

    elif context.get_context().dialect.name == 'mysql':
        drop_constraint(constraint_name='SOURCES_REPLICA_FK', table_name='sources', type_='foreignkey')
        # The constraint has an internal index which is not automatically dropped,
        # we have to do that manually
        drop_index('SOURCES_REPLICA_FK', 'sources')
        drop_constraint(constraint_name='REPLICAS_LFN_FK', table_name='replicas', type_='foreignkey')
        drop_constraint(constraint_name='REPLICAS_RSE_ID_FK', table_name='replicas', type_='foreignkey')
        drop_constraint(constraint_name='REPLICAS_PK', table_name='replicas', type_='primary')
        create_foreign_key('REPLICAS_LFN_FK', 'replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('REPLICAS_RSE_ID_FK', 'replicas', 'rses', ['rse_id'], ['id'])
        create_primary_key('REPLICAS_PK', 'replicas', ['rse_id', 'scope', 'name'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['rse_id', 'scope', 'name'], ['rse_id', 'scope', 'name'])
