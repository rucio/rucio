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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2019
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017

''' rename callback to message '''

from alembic import context
from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, rename_table)


# Alembic revision identifiers
revision = '58c8b78301ab'
down_revision = '2b8e7bcb4783'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name == 'oracle':
        drop_constraint('callbacks_pk', 'callbacks', type_='primary')
        rename_table('callbacks', 'messages')
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')

    elif context.get_context().dialect.name == 'postgresql':
        drop_constraint('callbacks_pk', 'callbacks', type_='primary')
        drop_constraint('callbacks_event_type_nn', 'callbacks', type_='check')
        drop_constraint('callbacks_payload_nn', 'callbacks', type_='check')
        drop_constraint('callbacks_created_nn', 'callbacks', type_='check')
        drop_constraint('callbacks_updated_nn', 'callbacks', type_='check')
        rename_table('callbacks', 'messages')
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')

    elif context.get_context().dialect.name == 'mysql':
        drop_constraint('callbacks_pk', 'callbacks', type_='primary')
        rename_table('callbacks', 'messages')
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name == 'oracle':
        drop_constraint('messages_event_type_nn', 'messages', type_='check')
        drop_constraint('messages_payload_nn', 'messages', type_='check')
        drop_constraint('messages_created_nn', 'messages', type_='check')
        drop_constraint('messages_updated_nn', 'messages', type_='check')
        drop_constraint('messages_pk', 'messages', type_='primary')
        rename_table('messages', 'callbacks')
        create_primary_key('callbacks_pk', 'callbacks', ['id'])
        create_check_constraint('callbacks_event_type_nn', 'callbacks', 'event_type is not null')
        create_check_constraint('callbacks_payload_nn', 'callbacks', 'payload is not null')
        create_check_constraint('callbacks_created_nn', 'callbacks', 'created_at is not null')
        create_check_constraint('callbacks_updated_nn', 'callbacks', 'updated_at is not null')

    elif context.get_context().dialect.name == 'postgresql':
        pass

    elif context.get_context().dialect.name == 'mysql':
        drop_constraint('messages_pk', 'messages', type_='primary')
        rename_table('messages', 'callbacks')
        create_primary_key('callbacks_pk', 'callbacks', ['id'])
        create_check_constraint('callbacks_event_type_nn', 'callbacks', 'event_type is not null')
        create_check_constraint('callbacks_payload_nn', 'callbacks', 'payload is not null')
        create_check_constraint('callbacks_created_nn', 'callbacks', 'created_at is not null')
        create_check_constraint('callbacks_updated_nn', 'callbacks', 'updated_at is not null')
