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

''' Removal of ReplicaState.SOURCE '''

from alembic import context
from alembic.op import (create_check_constraint, drop_constraint)


# Alembic revision identifiers
revision = 'b7d287de34fd'
down_revision = 'f1b14a8c2ac1'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('REPLICAS_STATE_CHK', 'replicas', type_='check')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")
        drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas', type_='check')
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'T')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_constraint('REPLICAS_STATE_CHK', 'replicas', type_='check')
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        drop_constraint('COLLECTION_REPLICAS_STATE_CHK', 'collection_replicas', type_='check')
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")

    elif context.get_context().dialect.name == 'mysql':
        create_check_constraint(constraint_name='REPLICAS_STATE_CHK', table_name='replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        create_check_constraint(constraint_name='COLLECTION_REPLICAS_STATE_CHK', table_name='collection_replicas',
                                condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
