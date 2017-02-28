# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""add mismatch scheme state to requests

Revision ID: 21d6b9dc9961
Revises: 5f139f77382a
Create Date: 2016-07-08 15:46:23.859031

"""

from alembic import context
from alembic.op import create_check_constraint, drop_constraint


# revision identifiers, used by Alembic.
revision = '21d6b9dc9961'
down_revision = '5f139f77382a'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M')")


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W')")
