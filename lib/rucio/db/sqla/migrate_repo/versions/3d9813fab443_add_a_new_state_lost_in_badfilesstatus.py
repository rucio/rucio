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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' add a new state LOST in BadFilesStatus '''

from alembic import context
from alembic.op import create_check_constraint

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '3d9813fab443'
down_revision = '1fc15ab60d43'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")


def downgrade():

    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        try_drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas')
