# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""rename callback to message

Revision ID: 58c8b78301ab
Revises: 2b8e7bcb4783
Create Date: 2014-05-09 09:50:36.321013

"""

from alembic import context
from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, rename_table)


# revision identifiers, used by Alembic.
revision = '58c8b78301ab'
down_revision = '2b8e7bcb4783'


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('callbacks_pk', 'callbacks', type_='primary')

    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('callbacks_event_type_nn', 'callbacks', type_='check')
        drop_constraint('callbacks_payload_nn', 'callbacks', type_='check')
        drop_constraint('callbacks_created_nn', 'callbacks', type_='check')
        drop_constraint('callbacks_updated_nn', 'callbacks', type_='check')

    rename_table('callbacks', 'messages')
    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('messages_pk', 'messages', ['id'])
        create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('messages_event_type_nn', 'messages', type_='check')
        drop_constraint('messages_payload_nn', 'messages', type_='check')
        drop_constraint('messages_created_nn', 'messages', type_='check')
        drop_constraint('messages_updated_nn', 'messages', type_='check')

    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('messages_pk', 'messages', type_='primary')

    rename_table('messages', 'callbacks')

    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('callbacks_pk', 'callbacks', ['id'])
        create_check_constraint('callbacks_event_type_nn', 'callbacks', 'event_type is not null')
        create_check_constraint('callbacks_payload_nn', 'callbacks', 'payload is not null')
        create_check_constraint('callbacks_created_nn', 'callbacks', 'created_at is not null')
        create_check_constraint('callbacks_updated_nn', 'callbacks', 'updated_at is not null')
