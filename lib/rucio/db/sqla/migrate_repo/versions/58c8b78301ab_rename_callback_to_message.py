# Copyright European Organization for Nuclear Research (CERN) since 2012
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

""" rename callback to message """

from rucio.db.sqla.migrate_repo import (
    create_check_constraint,
    create_primary_key,
    is_current_dialect,
    rename_table,
    try_drop_constraint,
    try_drop_primary_key,
)

# Alembic revision identifiers
revision = '58c8b78301ab'
down_revision = '2b8e7bcb4783'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle'):
        try_drop_primary_key('callbacks')
        rename_table('callbacks', 'messages')
        create_primary_key('messages_pk', 'messages', ['id'])
        # Remove any leftover constraints with either legacy or target names for idempotency.
        for chk in (
                'CALLBACKS_EVENT_TYPE_NN', 'CALLBACKS_PAYLOAD_NN', 'CALLBACKS_CREATED_NN', 'CALLBACKS_UPDATED_NN',
                'callbacks_event_type_nn', 'callbacks_payload_nn', 'callbacks_created_nn', 'callbacks_updated_nn',
                'MESSAGES_EVENT_TYPE_NN', 'MESSAGES_PAYLOAD_NN', 'MESSAGES_CREATED_NN', 'MESSAGES_UPDATED_NN',
                'messages_event_type_nn', 'messages_payload_nn', 'messages_created_nn', 'messages_updated_nn',
        ):
            try_drop_constraint(chk, 'messages')
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')

    elif is_current_dialect('postgresql'):
        try_drop_primary_key('callbacks')
        rename_table('callbacks', 'messages')
        create_primary_key('messages_pk', 'messages', ['id'])
        # Remove any leftover constraints with either legacy or target names for idempotency.
        for chk in (
                'CALLBACKS_EVENT_TYPE_NN', 'CALLBACKS_PAYLOAD_NN', 'CALLBACKS_CREATED_NN', 'CALLBACKS_UPDATED_NN',
                'callbacks_event_type_nn', 'callbacks_payload_nn', 'callbacks_created_nn', 'callbacks_updated_nn',
                'MESSAGES_EVENT_TYPE_NN', 'MESSAGES_PAYLOAD_NN', 'MESSAGES_CREATED_NN', 'MESSAGES_UPDATED_NN',
                'messages_event_type_nn', 'messages_payload_nn', 'messages_created_nn', 'messages_updated_nn',
        ):
            try_drop_constraint(chk, 'messages')
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')

    elif is_current_dialect('mysql'):
        try_drop_primary_key('callbacks')
        rename_table('callbacks', 'messages')
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('postgresql', 'oracle', 'mysql'):
        # Drop target-name variants on messages before renaming.
        for chk in (
                'MESSAGES_EVENT_TYPE_NN', 'MESSAGES_PAYLOAD_NN', 'MESSAGES_CREATED_NN', 'MESSAGES_UPDATED_NN',
                'messages_event_type_nn', 'messages_payload_nn', 'messages_created_nn', 'messages_updated_nn',
                # On MySQL, renaming a table keeps the original constraint names. When this downgrade
                # runs after the upgrade path, the callbacks_* constraints may still be attached to
                # the messages table, so drop them preemptively to avoid duplicate-name errors.
                'CALLBACKS_EVENT_TYPE_NN', 'CALLBACKS_PAYLOAD_NN', 'CALLBACKS_CREATED_NN', 'CALLBACKS_UPDATED_NN',
                'callbacks_event_type_nn', 'callbacks_payload_nn', 'callbacks_created_nn', 'callbacks_updated_nn',
        ):
            try_drop_constraint(chk, 'messages')

        try_drop_primary_key('messages')
        rename_table('messages', 'callbacks')
        create_primary_key('CALLBACKS_PK', 'callbacks', ['id'])
        create_check_constraint('CALLBACKS_EVENT_TYPE_NN', 'callbacks', 'event_type is not null')
        create_check_constraint('CALLBACKS_PAYLOAD_NN', 'callbacks', 'payload is not null')
        create_check_constraint('CALLBACKS_CREATED_NN', 'callbacks', 'created_at is not null')
        create_check_constraint('CALLBACKS_UPDATED_NN', 'callbacks', 'updated_at is not null')
