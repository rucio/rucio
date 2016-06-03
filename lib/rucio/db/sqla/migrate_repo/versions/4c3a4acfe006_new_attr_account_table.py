# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

"""new attr account table

Revision ID: 4c3a4acfe006
Revises: 25fc855625cf
Create Date: 2015-01-06 15:10:17.976558
"""

from alembic import context, op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4c3a4acfe006'
down_revision = '25fc855625cf'


def upgrade():
    op.create_table('account_attr_map',
                    sa.Column('account', sa.String(25)),
                    sa.Column('key', sa.String(255)),
                    sa.Column('value', sa.String(255)),
                    sa.Column('updated_at', sa.DateTime),
                    sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('ACCOUNT_ATTR_MAP_PK', 'account_attr_map', ['account', 'key'])
        op.create_check_constraint('ACCOUNT_ATTR_MAP_CREATED_NN', 'account_attr_map', 'created_at is not null')
        op.create_check_constraint('ACCOUNT_ATTR_MAP_UPDATED_NN', 'account_attr_map', 'updated_at is not null')
        op.create_foreign_key('ACCOUNT_ATTR_MAP_ACCOUNT_FK', 'account_attr_map', 'accounts', ['account'], ['account'])
        op.create_index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'account_attr_map', ['key', 'value'])


def downgrade():
    if context.get_context().dialect.name == 'postgresql':
        op.drop_constraint('ACCOUNT_ATTR_MAP_PK', 'account_attr_map', type_='primary')
        op.drop_constraint('ACCOUNT_ATTR_MAP_CREATED_NN', 'account_attr_map')
        op.drop_constraint('ACCOUNT_ATTR_MAP_UPDATED_NN', 'account_attr_map')
        op.drop_constraint('ACCOUNT_ATTR_MAP_ACCOUNT_FK', 'account_attr_map')
        op.drop_constraint('ACCOUNT_ATTR_MAP_RSE_ID_FK', 'account_attr_map')
        op.drop_index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'account_attr_map')
    op.drop_table('account_attr_map')
