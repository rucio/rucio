# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""extend request state

Revision ID: bb695f45c04
Revises: 269fee20dee9
Create Date: 2015-07-18 17:14:56.336450

"""

from alembic.op import (add_column, create_check_constraint,
                        drop_constraint, drop_column)
from alembic import context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'bb695f45c04'
down_revision = '3082b8cef557'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
        add_column('requests', sa.Column('submitter_id', sa.Integer()))
        add_column('sources', sa.Column('is_using', sa.Boolean()))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        drop_column('requests', 'submitter_id')
        drop_column('sources', 'is_using')
