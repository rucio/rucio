# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

"""Add a new state LOST in BadFilesStatus

Revision ID: 3d9813fab443
Revises: 1fc15ab60d43
Create Date: 2015-07-08 10:54:51.912140

"""

from alembic import context
from alembic.op import create_check_constraint, drop_constraint

# revision identifiers, used by Alembic.
revision = '3d9813fab443'
down_revision = '1fc15ab60d43'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        create_check_constraint(name='BAD_REPLICAS_STATE_CHK', source='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas', type_='check')
