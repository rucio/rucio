# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2016

"""New table for lifetime model exceptions

Revision ID: 914b8f02df38
Revises: fe8ea2fa9788
Create Date: 2016-08-31 14:19:54.933924

"""

from alembic import context
from alembic.op import (create_table, create_primary_key,
                        create_check_constraint, drop_table)
import sqlalchemy as sa

from rucio.db.sqla.constants import DIDType, LifetimeExceptionsState
from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '914b8f02df38'
down_revision = 'fe8ea2fa9788'


def upgrade():
    '''
    upgrade method
    '''
    create_table('lifetime_except',
                 sa.Column('id', GUID()),
                 sa.Column('scope', sa.String(25)),
                 sa.Column('name', sa.String(255)),
                 sa.Column('did_type', DIDType.db_type(name='LIFETIME_EXCEPT_DID_TYPE_CHK')),
                 sa.Column('account', sa.String(25)),
                 sa.Column('comments', sa.String(4000)),
                 sa.Column('pattern', sa.String(255)),
                 sa.Column('state', LifetimeExceptionsState.db_type(name='LIFETIME_EXCEPT_STATE_CHK')),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('expires_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))

    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('LIFETIME_EXCEPT_PK', 'lifetime_except', ['id', 'scope', 'name', 'did_type', 'account'])
        create_check_constraint('LIFETIME_EXCEPT_SCOPE_NN', 'lifetime_except', 'scope is not null')
        create_check_constraint('LIFETIME_EXCEPT_NAME_NN', 'lifetime_except', 'name is not null')
        create_check_constraint('LIFETIME_EXCEPT_DID_TYPE_NN', 'lifetime_except', 'did_type is not null')


def downgrade():
    '''
    downgrade method
    '''
    drop_table('lifetime_except')
