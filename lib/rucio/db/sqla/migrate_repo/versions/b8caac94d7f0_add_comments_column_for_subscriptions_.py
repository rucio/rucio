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
# - Martin Barisits <martin.barisits@cern.ch>, 2019
#
# Topic: Add comments column for subscriptions_history
# Revision ID: b8caac94d7f0
# Revises: 3345511706b8
# Creation Date: 2019-02-20 16:52:28.549840

from alembic.op import (add_column, drop_column)

from alembic import context

import sqlalchemy as sa


# revision identifiers used by alembic
revision = 'b8caac94d7f0'       # pylint: disable=invalid-name
down_revision = '3345511706b8'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    add_column('subscriptions_history', sa.Column('comments', sa.String(4000)))


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_column('subscriptions_history', 'comments')
