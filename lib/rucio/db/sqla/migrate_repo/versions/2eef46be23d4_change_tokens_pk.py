# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""change tokens pk

Revision ID: 2eef46be23d4
Revises: 58c8b78301ab
Create Date: 2014-05-30 10:47:46.880093

"""
from alembic import context
from alembic.op import create_primary_key, create_foreign_key, drop_constraint


# revision identifiers, used by Alembic.
revision = '2eef46be23d4'
down_revision = '58c8b78301ab'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('tokens_account_fk', 'tokens', type_='foreignkey')
        drop_constraint('tokens_pk', 'tokens', type_='primary')
        create_primary_key('tokens_pk', 'tokens', ['token'])
        create_foreign_key('tokens_account_fk', 'tokens', 'accounts', ['account'], ['account'])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('tokens_account_fk', 'tokens', type_='foreignkey')
        drop_constraint('tokens_pk', 'tokens', type_='primary')
        create_primary_key('tokens_pk', 'tokens', ['account', 'token'])
        create_foreign_key('tokens_account_fk', 'tokens', 'accounts', ['account'], ['account'])
