# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""rename callback to message

Revision ID: 58c8b78301ab
Revises: 2b8e7bcb4783
Create Date: 2014-05-09 09:50:36.321013

"""

from alembic import context, op

# revision identifiers, used by Alembic.
revision = '58c8b78301ab'
down_revision = '2b8e7bcb4783'


def upgrade():

    if context.get_context().dialect.name != 'sqlite':
        op.drop_constraint('callbacks_pk', 'callbacks', type_='primary')

    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        op.drop_constraint('callbacks_event_type_nn', 'callbacks', type_='check')
        op.drop_constraint('callbacks_payload_nn', 'callbacks', type_='check')
        op.drop_constraint('callbacks_created_nn', 'callbacks', type_='check')
        op.drop_constraint('callbacks_updated_nn', 'callbacks', type_='check')

    op.rename_table('callbacks', 'messages')
    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('messages_pk', 'messages', ['id'])
        op.create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
        op.create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
        op.create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
        op.create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')


def downgrade():

    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        op.drop_constraint('messages_event_type_nn', 'messages', type_='check')
        op.drop_constraint('messages_payload_nn', 'messages', type_='check')
        op.drop_constraint('messages_created_nn', 'messages', type_='check')
        op.drop_constraint('messages_updated_nn', 'messages', type_='check')

    if context.get_context().dialect.name != 'sqlite':
        op.drop_constraint('messages_pk', 'messages', type_='primary')

    op.rename_table('messages', 'callbacks')

    if context.get_context().dialect.name != 'sqlite':
        op.create_primary_key('callbacks_pk', 'callbacks', ['id'])
        op.create_check_constraint('callbacks_event_type_nn', 'callbacks', 'event_type is not null')
        op.create_check_constraint('callbacks_payload_nn', 'callbacks', 'payload is not null')
        op.create_check_constraint('callbacks_created_nn', 'callbacks', 'created_at is not null')
        op.create_check_constraint('callbacks_updated_nn', 'callbacks', 'updated_at is not null')
