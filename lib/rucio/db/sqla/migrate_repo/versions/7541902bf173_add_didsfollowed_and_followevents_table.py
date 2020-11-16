# -*- coding: utf-8 -*-
# Copyright 2019-2020 CERN
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
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

''' add DidsFollowed and FollowEvents table '''

import sqlalchemy as sa
import datetime

from alembic import context
from alembic.op import (create_table, create_primary_key, create_check_constraint,
                        create_foreign_key, create_index, drop_table)

from rucio.db.sqla.constants import DIDType

# Alembic revision identifiers
revision = '7541902bf173'
down_revision = 'a74275a1ad30'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('dids_followed',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('did_type', sa.Enum(DIDType, name='DIDS_FOLLOWED_TYPE_CHK', values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow))

        create_primary_key('DIDS_FOLLOWED_PK', 'dids_followed', ['scope', 'name', 'account'])
        create_check_constraint('DIDS_FOLLOWED_SCOPE_NN', 'dids_followed', 'scope is not null')
        create_check_constraint('DIDS_FOLLOWED_NAME_NN', 'dids_followed', 'name is not null')
        create_check_constraint('DIDS_FOLLOWED_ACCOUNT_NN', 'dids_followed', 'account is not null')
        create_check_constraint('DIDS_FOLLOWED_DID_TYPE_NN', 'dids_followed', 'did_type is not null')
        create_check_constraint('DIDS_FOLLOWED_CREATED_NN', 'dids_followed', 'created_at is not null')
        create_check_constraint('DIDS_FOLLOWED_UPDATED_NN', 'dids_followed', 'updated_at is not null')
        create_foreign_key('DIDS_FOLLOWED_ACCOUNT_FK', 'dids_followed', 'accounts',
                           ['account'], ['account'])
        create_foreign_key('DIDS_FOLLOWED_SCOPE_NAME_FK', 'dids_followed', 'dids',
                           ['scope', 'name'], ['scope', 'name'])

        create_table('dids_followed_events',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('did_type', sa.Enum(DIDType, name='DIDS_FOLLOWED_EVENTS_TYPE_CHK', values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('event_type', sa.String(1024)),
                     sa.Column('payload', sa.Text),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow))

        create_primary_key('DIDS_FOLLOWED_EVENTS_PK', 'dids_followed_events', ['scope', 'name', 'account'])
        create_check_constraint('DIDS_FOLLOWED_EVENTS_SCOPE_NN', 'dids_followed_events', 'scope is not null')
        create_check_constraint('DIDS_FOLLOWED_EVENTS_NAME_NN', 'dids_followed_events', 'name is not null')
        create_check_constraint('DIDS_FOLLOWED_EVENTS_ACC_NN', 'dids_followed_events', 'account is not null')
        create_check_constraint('DIDS_FOLLOWED_EVENTS_TYPE_NN', 'dids_followed_events', 'did_type is not null')
        create_check_constraint('DIDS_FOLLOWED_EVENTS_CRE_NN', 'dids_followed_events', 'created_at is not null')
        create_check_constraint('DIDS_FOLLOWED_EVENTS_UPD_NN', 'dids_followed_events', 'updated_at is not null')
        create_foreign_key('DIDS_FOLLOWED_EVENTS_ACC_FK', 'dids_followed_events', 'accounts',
                           ['account'], ['account'])
        create_index('DIDS_FOLLOWED_EVENTS_ACC_IDX', 'dids_followed_events', ['account'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('dids_followed')
        drop_table('dids_followed_events')
