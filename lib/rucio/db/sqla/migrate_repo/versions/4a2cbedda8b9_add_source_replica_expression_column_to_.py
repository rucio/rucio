# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""add_source_replica_expression_column_to_rules

Revision ID: 4a2cbedda8b9
Revises: a616581ee47
Create Date: 2014-07-11 15:59:48.245367

"""

from alembic import context
from alembic.op import add_column, drop_column

import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4a2cbedda8b9'
down_revision = 'a616581ee47'


def upgrade():
    '''
    upgrade method
    '''
    add_column('rules', sa.Column('source_replica_expression', sa.String(255)))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('rules', 'source_replica_expression')
