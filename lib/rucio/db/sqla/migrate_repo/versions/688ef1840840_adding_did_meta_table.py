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
# - Asket Agarwal, <asket.agarwal96@gmail.com>, 2018
# Adding did_meta table
#
# Revision ID: 688ef1840840
# Revises: b818052fa670
# Create Date: 2018-06-02 08:15:37.614522

from alembic.op import create_primary_key, create_table, create_foreign_key, drop_table

from alembic import context

import sqlalchemy as sa
from rucio.db.sqla.types import JSON


# revision identifiers, used by Alembic.
revision = '688ef1840840'  # pylint: disable=invalid-name
down_revision = 'b818052fa670'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_table('did_meta',
                 sa.Column('scope', sa.String(25)),
                 sa.Column('name', sa.String(255)),
                 sa.Column('meta', JSON()))

    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('DID_META_PK', 'did_meta', ['scope', 'name'])
        create_foreign_key('DID_META_FK', 'did_meta', 'dids',
                           ['scope', 'name'], ['scope', 'name'])


def downgrade():
    '''
    downgrade method
    '''
    drop_table('did_meta')
