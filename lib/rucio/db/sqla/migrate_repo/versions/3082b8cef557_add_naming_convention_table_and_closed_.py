# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

"""add naming convention table and closed to dids table

Revision ID: 3082b8cef557
Revises: 269fee20dee9
Create Date: 2015-07-30 10:31:14.899287

"""

from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3082b8cef557'
down_revision = '269fee20dee9'


def upgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.add_column('dids', sa.Column('closed_at', sa.DateTime))
        op.add_column('contents_history', sa.Column('deleted_at', sa.DateTime))
        op.create_table('naming_conventions',
                        sa.Column('scope', sa.String(25)),
                        sa.Column('regexp', sa.String(255)),
                        sa.Column('convention_type', sa.String(1)),
                        sa.Column('updated_at', sa.DateTime),
                        sa.Column('created_at', sa.DateTime))
        op.create_primary_key('NAMING_CONVENTIONS_PK', 'naming_conventions', ['scope'])
        op.create_foreign_key('NAMING_CONVENTIONS_SCOPE_FK', 'naming_conventions',
                              'scopes', ['scope'], ['scope'])
        op.create_check_constraint('NAMING_CONVENTIONS_CREATED_NN', 'naming_conventions',
                                   'created_at is not null')
        op.create_check_constraint('NAMING_CONVENTIONS_UPDATED_NN', 'naming_conventions',
                                   'updated_at is not null')


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_column('dids', 'closed_at')
        op.drop_column('contents_history', 'deleted_at')
        op.drop_table('naming_conventions')
