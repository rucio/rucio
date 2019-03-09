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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' add columns for 1.7.0 release '''

import sqlalchemy as sa

from alembic import context
from alembic.op import create_check_constraint, create_foreign_key, add_column, drop_column, drop_constraint


# Alembic revision identifiers
revision = 'a5f6f6e928a7'
down_revision = '21d6b9dc9961'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        add_column('dids', sa.Column('purge_replicas',
                                     sa.Boolean(name='DIDS_PURGE_RPLCS_CHK'),
                                     server_default='1'))
        add_column('dids', sa.Column('eol_at', sa.DateTime))

        add_column('deleted_dids', sa.Column('purge_replicas',
                                             sa.Boolean(name='DEL_DIDS_PURGE_RPLCS_CHK')))
        add_column('deleted_dids', sa.Column('eol_at', sa.DateTime))

        create_check_constraint('DIDS_PURGE_REPLICAS_NN', 'dids', 'purge_replicas is not null')

        add_column('requests', sa.Column('account', sa.String(25)))
        add_column('requests', sa.Column('requested_at', sa.DateTime))
        add_column('requests', sa.Column('priority', sa.Integer))
        create_foreign_key('REQUESTS_ACCOUNT_FK', 'requests', 'accounts', ['account'], ['account'])

        add_column('requests_history', sa.Column('account', sa.String(25)))
        add_column('requests_history', sa.Column('requested_at', sa.DateTime))

        add_column('requests_history', sa.Column('priority', sa.Integer))

        add_column('rules', sa.Column('priority', sa.Integer))
        add_column('rules_hist_recent', sa.Column('priority', sa.Integer))
        add_column('rules_history', sa.Column('priority', sa.Integer))

        add_column('distances', sa.Column('active', sa.Integer))
        add_column('distances', sa.Column('submitted', sa.Integer))
        add_column('distances', sa.Column('finished', sa.Integer))
        add_column('distances', sa.Column('failed', sa.Integer))
        add_column('distances', sa.Column('transfer_speed', sa.Integer))

    elif context.get_context().dialect.name == 'postgresql':
        pass


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        drop_column('dids', 'purge_replicas')
        drop_column('dids', 'eol_at')

        drop_column('deleted_dids', 'purge_replicas')
        drop_column('deleted_dids', 'eol_at')

        drop_column('requests', 'account')
        drop_column('requests', 'requested_at')
        drop_column('requests', 'priority')

        drop_column('requests_history', 'account')
        drop_column('requests_history', 'requested_at')
        drop_column('requests_history', 'priority')

        drop_column('rules', 'priority')
        drop_column('rules_hist_recent', 'priority')
        drop_column('rules_history', 'priority')

        drop_column('distances', 'active')
        drop_column('distances', 'submitted')
        drop_column('distances', 'finished')
        drop_column('distances', 'failed')
        drop_column('distances', 'transfer_speed')

    elif context.get_context().dialect.name == 'postgresql':
        pass

    elif context.get_context().dialect.name == 'mysql':
        drop_column('dids', 'purge_replicas')
        drop_column('dids', 'eol_at')

        drop_column('deleted_dids', 'purge_replicas')
        drop_column('deleted_dids', 'eol_at')

        drop_constraint(constraint_name='REQUESTS_ACCOUNT_FK', table_name='requests', type_='foreignkey')
        drop_column('requests', 'account')
        drop_column('requests', 'requested_at')
        drop_column('requests', 'priority')

        drop_column('requests_history', 'account')
        drop_column('requests_history', 'requested_at')
        drop_column('requests_history', 'priority')

        drop_column('rules', 'priority')
        drop_column('rules_hist_recent', 'priority')
        drop_column('rules_history', 'priority')

        drop_column('distances', 'active')
        drop_column('distances', 'submitted')
        drop_column('distances', 'finished')
        drop_column('distances', 'failed')
        drop_column('distances', 'transfer_speed')
