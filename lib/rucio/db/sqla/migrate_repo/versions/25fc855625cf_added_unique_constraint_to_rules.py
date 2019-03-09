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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017

''' added unique constraint to rules '''

from alembic import context
from alembic.op import create_index, drop_index


# Alembic revision identifiers
revision = '25fc855625cf'
down_revision = '4a7182d9578b'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_index('RULES_SC_NA_AC_RS_CO_UQ_IDX', 'rules', ['scope', 'name', 'account', 'rse_expression', 'copies'],
                     unique=True, mysql_length={'rse_expression': 767})

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_index('RULES_SC_NA_AC_RS_CO_UQ_IDX', 'rules')

    elif context.get_context().dialect.name == 'postgresql':
        pass
