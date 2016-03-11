# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015

"""Added comment column to rules

Revision ID: ae2a56fcc89
Revises: 45378a1e76a8
Create Date: 2015-03-10 13:51:10.950899

"""

import sqlalchemy as sa

from alembic import context, op
from rucio.db.sqla.models import String

# revision identifiers, used by Alembic.
revision = 'ae2a56fcc89'
down_revision = '45378a1e76a8'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.add_column('rules', sa.Column('comments', String(255)))
        op.add_column('rules_hist_recent', sa.Column('comments', String(255)))
        op.add_column('rules_history', sa.Column('comments', String(255)))


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_column('rules', 'comments')
        op.drop_column('rules_hist_recent', 'comments')
        op.drop_column('rules_history', 'comments')
