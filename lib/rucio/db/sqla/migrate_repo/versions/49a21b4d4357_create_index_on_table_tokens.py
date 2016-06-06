# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

"""add tokens index

Revision ID: 49a21b4d4357
Revises: 2eef46be23d4
Create Date: 2014-06-11 09:02:49.654877

"""

from alembic import context, op

# revision identifiers, used by Alembic.
revision = '49a21b4d4357'
down_revision = '2eef46be23d4'


def upgrade():

    if context.get_context().dialect.name != 'sqlite':
        op.drop_constraint('tokens_account_fk', 'tokens', type_='foreignkey')
        op.create_index('TOKENS_ACCOUNT_EXPIRED_AT_IDX', 'tokens', ['account', 'expired_at'])
        op.create_foreign_key('tokens_account_fk', 'tokens', 'accounts', ['account'], ['account'])


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_constraint('tokens_account_fk', 'tokens', type_='foreignkey')
        op.drop_index('TOKENS_ACCOUNT_EXPIRED_AT_IDX', 'tokens')
        op.create_foreign_key('tokens_account_fk', 'tokens', 'accounts', ['account'], ['account'])
