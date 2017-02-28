# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017

"""new attr account table

Revision ID: 4c3a4acfe006
Revises: 25fc855625cf
Create Date: 2015-01-06 15:10:17.976558
"""

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index,
                        drop_constraint, drop_table, drop_index)
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4c3a4acfe006'
down_revision = '25fc855625cf'


def upgrade():
    '''
    upgrade method
    '''
    create_table('account_attr_map',
                 sa.Column('account', sa.String(25)),
                 sa.Column('key', sa.String(255)),
                 sa.Column('value', sa.String(255)),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('ACCOUNT_ATTR_MAP_PK', 'account_attr_map', ['account', 'key'])
        create_check_constraint('ACCOUNT_ATTR_MAP_CREATED_NN', 'account_attr_map', 'created_at is not null')
        create_check_constraint('ACCOUNT_ATTR_MAP_UPDATED_NN', 'account_attr_map', 'updated_at is not null')
        create_foreign_key('ACCOUNT_ATTR_MAP_ACCOUNT_FK', 'account_attr_map', 'accounts', ['account'], ['account'])
        create_index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'account_attr_map', ['key', 'value'])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name == 'postgresql':
        drop_constraint('ACCOUNT_ATTR_MAP_PK', 'account_attr_map', type_='primary')
        drop_constraint('ACCOUNT_ATTR_MAP_CREATED_NN', 'account_attr_map')
        drop_constraint('ACCOUNT_ATTR_MAP_UPDATED_NN', 'account_attr_map')
        drop_constraint('ACCOUNT_ATTR_MAP_ACCOUNT_FK', 'account_attr_map')
        drop_constraint('ACCOUNT_ATTR_MAP_RSE_ID_FK', 'account_attr_map')
        drop_index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'account_attr_map')
    drop_table('account_attr_map')
