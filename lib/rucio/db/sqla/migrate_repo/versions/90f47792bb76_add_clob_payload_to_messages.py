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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
#
# Topic: True is true
# Revision ID: 90f47792bb76
# Revises: 1f46c5f240ac
# Creation Date: 2019-01-21 15:35:22.732801

from alembic.op import add_column, drop_column

import sqlalchemy as sa

# revision identifiers used by alembic
revision = '90f47792bb76'       # pylint: disable=invalid-name
down_revision = 'bf3baa1c1474'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    add_column('messages', sa.Column('payload_nolimit', sa.Text))
    add_column('messages_history', sa.Column('payload_nolimit', sa.Text))


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    drop_column('messages', 'payload_nolimit')
    drop_column('messages_history', 'payload_nolimit')
