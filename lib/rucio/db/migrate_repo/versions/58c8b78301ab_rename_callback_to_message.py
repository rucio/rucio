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

# revision identifiers, used by Alembic.
revision = '58c8b78301ab'
down_revision = '2b8e7bcb4783'

from alembic import op


def upgrade():
    op.drop_constraint('callbacks_pk', 'callbacks')
    op.drop_constraint('callbacks_event_type_nn', 'callbacks')
    op.drop_constraint('callbacks_payload_nn', 'callbacks')
    op.drop_constraint('callbacks_created_nn', 'callbacks')
    op.drop_constraint('callbacks_updated_nn', 'callbacks')
    op.rename_table('callbacks', 'messages')
    op.create_primary_key('messages_pk', 'messages', ['id'])
    op.create_check_constraint('messages_event_type_nn', 'messages', 'event_type is not null')
    op.create_check_constraint('messages_payload_nn', 'messages', 'payload is not null')
    op.create_check_constraint('messages_created_nn', 'messages', 'created_at is not null')
    op.create_check_constraint('messages_updated_nn', 'messages', 'updated_at is not null')


def downgrade():
    op.drop_constraint('messages_pk', 'messages')
    op.drop_constraint('messages_event_type_nn', 'messages')
    op.drop_constraint('messages_payload_nn', 'messages')
    op.drop_constraint('messages_created_nn', 'messages')
    op.drop_constraint('messages_updated_nn', 'messages')
    op.rename_table('messages', 'callbacks')
    op.create_primary_key('callbacks_pk', 'callbacks', ['id'])
    op.create_check_constraint('callbacks_event_type_nn', 'callbacks', 'event_type is not null')
    op.create_check_constraint('callbacks_payload_nn', 'callbacks', 'payload is not null')
    op.create_check_constraint('callbacks_created_nn', 'callbacks', 'created_at is not null')
    op.create_check_constraint('callbacks_updated_nn', 'callbacks', 'updated_at is not null')
