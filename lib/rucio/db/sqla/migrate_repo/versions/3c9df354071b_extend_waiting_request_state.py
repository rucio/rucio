# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""extend waiting request state

Revision ID: 3c9df354071b
Revises: 2edee4a83846
Create Date: 2015-10-24 14:28:11.610651

"""

from alembic import context
from alembic.op import create_check_constraint, drop_constraint

# revision identifiers, used by Alembic.
revision = '3c9df354071b'
down_revision = '2edee4a83846'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U','W')")


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
