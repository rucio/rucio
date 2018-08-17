# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# Add bytes column to bad_replicas
#
# Revision ID: 1f46c5f240ac
# Revises: 688ef1840840
# Create Date: 2018-07-26 15:28:04.243520

from alembic.op import add_column, drop_column
from alembic import context

import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1f46c5f240ac'  # pylint: disable=invalid-name
down_revision = '688ef1840840'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':  # pylint: disable=no-member
        add_column('bad_replicas', sa.Column('bytes', sa.BigInteger))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':  # pylint: disable=no-member
        drop_column('bad_replicas', 'bytes')
