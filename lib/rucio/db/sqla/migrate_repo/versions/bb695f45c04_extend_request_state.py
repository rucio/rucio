# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015

"""extend request state

Revision ID: bb695f45c04
Revises: 269fee20dee9
Create Date: 2015-07-18 17:14:56.336450

"""

from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'bb695f45c04'
down_revision = '3082b8cef557'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        op.drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        op.create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U')")
        op.add_column('requests', sa.Column('submitter_id', sa.Integer()))
        op.add_column('sources', sa.Column('is_using', sa.Boolean()))


def downgrade():
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        op.drop_constraint('REQUESTS_STATE_CHK', 'requests', type_='check')
        op.create_check_constraint(name='REQUESTS_STATE_CHK', source='requests', condition="state in ('Q', 'G', 'S', 'D', 'F', 'L')")
        op.drop_column('requests', 'submitter_id')
        op.drop_column('sources', 'is_using')
