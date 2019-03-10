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

''' index in rule_history on scope, name '''

from alembic import context
from alembic.op import create_index, drop_index


# Alembic revision identifiers
revision = '2f648fc909f3'
down_revision = 'bb695f45c04'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_index('RULES_HISTORY_SCOPENAME_IDX', 'rules_history', ['scope', 'name'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_index('RULES_HISTORY_SCOPENAME_IDX', 'rules_history')
