# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2016
# - Cedric Serfon, <vincent.garonne@cern.ch>, 2016

"""Add eol_at in rules

Revision ID: 0437a40dbfd1
Revises: a5f6f6e928a7
Create Date: 2016-08-04 13:06:39.424799

"""

from alembic import context, op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0437a40dbfd1'
down_revision = 'a5f6f6e928a7'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.add_column('rules', sa.Column('eol_at', sa.DateTime))
        op.add_column('rules_hist_recent', sa.Column('eol_at', sa.DateTime))
        op.add_column('rules_history', sa.Column('eol_at', sa.DateTime))


def downgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_column('rules', 'eol_at')
        op.drop_column('rules_hist_recent', 'eol_at')
        op.drop_column('rules_history', 'eol_at')
