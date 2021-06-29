# Copyright 2015-2021 CERN
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
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019-2021

''' rename callback to message '''

from alembic import context, op
from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, rename_table)

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '58c8b78301ab'
down_revision = '2b8e7bcb4783'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

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
        rename_table('callbacks', 'messages', schema=schema[:-1])
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')

    elif context.get_context().dialect.name == 'mysql':
        drop_constraint('callbacks_pk', 'callbacks', type_='primary')
        rename_table('callbacks', 'messages', schema=schema[:-1])
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name == 'oracle':
        try_drop_constraint('MESSAGES_EVENT_TYPE_NN', 'messages')
        try_drop_constraint('MESSAGES_PAYLOAD_NN', 'messages')
        try_drop_constraint('MESSAGES_CREATED_NN', 'messages')
        try_drop_constraint('MESSAGES_UPDATED_NN', 'messages')
        drop_constraint('MESSAGES_PK', 'messages', type_='primary')
        rename_table('messages', 'callbacks')
        create_primary_key('CALLBACKS_PK', 'callbacks', ['id'])
        create_check_constraint('CALLBACKS_EVENT_TYPE_NN', 'callbacks', 'event_type is not null')
        create_check_constraint('CALLBACKS_PAYLOAD_NN', 'callbacks', 'payload is not null')
        create_check_constraint('CALLBACKS_CREATED_NN', 'callbacks', 'created_at is not null')
        create_check_constraint('CALLBACKS_UPDATED_NN', 'callbacks', 'updated_at is not null')

    elif context.get_context().dialect.name == 'postgresql':
        drop_constraint('MESSAGES_EVENT_TYPE_NN', 'messages', type_='check')
        drop_constraint('MESSAGES_PAYLOAD_NN', 'messages', type_='check')
        drop_constraint('MESSAGES_CREATED_NN', 'messages', type_='check')
        drop_constraint('MESSAGES_UPDATED_NN', 'messages', type_='check')
        drop_constraint('MESSAGES_PK', 'messages', type_='primary')
        rename_table('messages', 'callbacks', schema=schema[:-1])
        create_primary_key('CALLBACKS_PK', 'callbacks', ['id'])
        create_check_constraint('CALLBACKS_EVENT_TYPE_NN', 'callbacks', 'event_type is not null')
        create_check_constraint('CALLBACKS_PAYLOAD_NN', 'callbacks', 'payload is not null')
        create_check_constraint('CALLBACKS_CREATED_NN', 'callbacks', 'created_at is not null')
        create_check_constraint('CALLBACKS_UPDATED_NN', 'callbacks', 'updated_at is not null')

    elif context.get_context().dialect.name == 'mysql':
        op.execute('ALTER TABLE ' + schema + 'messages DROP CHECK MESSAGES_EVENT_TYPE_NN')  # pylint: disable=no-member
        op.execute('ALTER TABLE ' + schema + 'messages DROP CHECK MESSAGES_PAYLOAD_NN')  # pylint: disable=no-member
        op.execute('ALTER TABLE ' + schema + 'messages DROP CHECK MESSAGES_CREATED_NN')  # pylint: disable=no-member
        op.execute('ALTER TABLE ' + schema + 'messages DROP CHECK MESSAGES_UPDATED_NN')  # pylint: disable=no-member
        drop_constraint('messages_pk', 'messages', type_='primary')
        rename_table('messages', 'callbacks', schema=schema[:-1])
        create_primary_key('callbacks_pk', 'callbacks', ['id'])
        create_check_constraint('callbacks_event_type_nn', 'callbacks', 'event_type is not null')
        create_check_constraint('callbacks_payload_nn', 'callbacks', 'payload is not null')
        create_check_constraint('callbacks_created_nn', 'callbacks', 'created_at is not null')
        create_check_constraint('callbacks_updated_nn', 'callbacks', 'updated_at is not null')
