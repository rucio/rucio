# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

"""added_rule_id_column

Revision ID: 2854cd9e168
Revises: 35ef10d1e11b
Create Date: 2014-07-04 09:18:34.826987

"""

import sqlalchemy as sa

from alembic import context, op

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '2854cd9e168'
down_revision = '35ef10d1e11b'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.add_column('requests', sa.Column('rule_id', GUID()))
        op.add_column('requests_history', sa.Column('rule_id', GUID()))


def downgrade():
    op.drop_column('requests', 'rule_id')
    op.drop_column('requests_history', 'rule_id')
