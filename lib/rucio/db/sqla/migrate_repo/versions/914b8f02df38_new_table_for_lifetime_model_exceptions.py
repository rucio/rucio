# -*- coding: utf-8 -*-
# Copyright 2016-2020 CERN
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019-2020

''' new table for lifetime model exceptions '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key,
                        create_check_constraint, drop_table)

from rucio.db.sqla.constants import DIDType, LifetimeExceptionsState
from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '914b8f02df38'
down_revision = 'fe8ea2fa9788'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('lifetime_except',
                     sa.Column('id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('did_type', sa.Enum(DIDType, name='LIFETIME_EXCEPT_TYPE_CHK', values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('account', sa.String(25)),
                     sa.Column('comments', sa.String(4000)),
                     sa.Column('pattern', sa.String(255)),
                     sa.Column('state', sa.Enum(LifetimeExceptionsState, name='LIFETIME_EXCEPT_STATE_CHK', values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                     sa.Column('expires_at', sa.DateTime))

        create_primary_key('LIFETIME_EXCEPT_PK', 'lifetime_except', ['id', 'scope', 'name', 'did_type', 'account'])
        create_check_constraint('LIFETIME_EXCEPT_SCOPE_NN', 'lifetime_except', 'scope is not null')
        create_check_constraint('LIFETIME_EXCEPT_NAME_NN', 'lifetime_except', 'name is not null')
        create_check_constraint('LIFETIME_EXCEPT_DID_TYPE_NN', 'lifetime_except', 'did_type is not null')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('lifetime_except')
