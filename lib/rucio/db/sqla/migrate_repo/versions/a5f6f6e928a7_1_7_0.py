# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016-2017

"""1.7.0

Revision ID: a5f6f6e928a7
Revises: 21d6b9dc9961
Create Date: 2016-07-25 10:21:20.117322

"""

from alembic.op import create_check_constraint, create_foreign_key, add_column, drop_column
from alembic import context
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a5f6f6e928a7'
down_revision = '21d6b9dc9961'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):
        # add purge replicas to dids/dids history
        add_column('dids', sa.Column('purge_replicas',
                                     sa.Boolean(name='DIDS_PURGE_REPLICAS_CHK'),
                                     default=True))
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


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):

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
