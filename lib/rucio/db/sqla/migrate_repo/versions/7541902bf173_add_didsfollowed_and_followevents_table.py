# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019

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
                     sa.Column('did_type', DIDType.db_type()),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow))

        create_primary_key('DIDS_FOLLOWED_PK', 'dids_followed', ['scope', 'name', 'account'])
        create_check_constraint('DIDS_FOLLOWED_SCOPE_NN', 'dids_followed', 'scope is not null')
        create_check_constraint('DIDS_FOLLOWED_NAME_NN', 'dids_followed', 'name is not null')
        create_check_constraint('DIDS_FOLLOWED_DID_TYPE_NN', 'dids_followed', 'did_type is not null')
        create_foreign_key('DIDS_FOLLOWED_ACCOUNT_FK', 'dids_followed', 'accounts',
                           ['account'], ['account'])
        create_foreign_key('DIDS_FOLLOWED_SCOPE_NAME_FK', 'dids_followed', 'dids',
                           ['scope', 'name'], ['scope', 'name'])

        create_table('follow_events',
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('account', sa.String(25)),
                     sa.Column('did_type', DIDType.db_type()),
                     sa.Column('event_type', sa.String(1024)),
                     sa.Column('payload', sa.Text),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow))

        create_primary_key('FOLLOW_EVENTS_PK', 'follow_events', ['scope', 'name', 'account'])
        create_check_constraint('FOLLOW_EVENTS_SCOPE_NN', 'follow_events', 'scope is not null')
        create_check_constraint('FOLLOW_EVENTS_NAME_NN', 'follow_events', 'name is not null')
        create_check_constraint('FOLLOW_EVENTS_DID_TYPE_NN', 'follow_events', 'did_type is not null')
        create_foreign_key('FOLLOW_EVENTS_ACCOUNT_FK', 'follow_events', 'accounts',
                           ['account'], ['account'])
        create_index('FOLLOW_EVENTS_ACCOUNT_IDX', 'follow_events', ['account'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('dids_followed')
        drop_table('follow_events')
