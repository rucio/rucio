# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""change tokens pk

Revision ID: 2eef46be23d4
Revises: 58c8b78301ab
Create Date: 2014-05-30 10:47:46.880093

"""

from alembic import context, op

# revision identifiers, used by Alembic.
revision = '2eef46be23d4'
down_revision = '58c8b78301ab'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_constraint('tokens_account_fk', 'tokens', type_='foreignkey')
        op.drop_constraint('tokens_pk', 'tokens', type_='primary')
        op.create_primary_key('tokens_pk', 'tokens', ['token'])
        op.create_foreign_key('tokens_account_fk', 'tokens', 'accounts', ['account'], ['account'])


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_constraint('tokens_account_fk', 'tokens', type_='foreignkey')
        op.drop_constraint('tokens_pk', 'tokens', type_='primary')
        op.create_primary_key('tokens_pk', 'tokens', ['account', 'token'])
        op.create_foreign_key('tokens_account_fk', 'tokens', 'accounts', ['account'], ['account'])
