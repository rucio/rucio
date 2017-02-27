# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits <martin.barisits@cern.ch>, 2014

"""Added purge column to rules

Revision ID: d6dceb1de2d
Revises: c129ccdb2d5
Create Date: 2014-11-12 14:01:14.996892

"""

from alembic.op import add_column, drop_column
from alembic import context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd6dceb1de2d'
down_revision = '25821a8a45a3'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        add_column('rules', sa.Column('purge_replicas', sa.Boolean(name='RULES_PURGE_REPLICAS_CHK'), default=False))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('rules', 'purge_replicas')
