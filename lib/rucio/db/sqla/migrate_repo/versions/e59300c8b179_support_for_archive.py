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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' support for archive '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key, add_column,
                        create_index, drop_column, drop_table)

from rucio.db.sqla.models import String
from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = 'e59300c8b179'
down_revision = '6e572a9bfbf3'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('archive_contents',
                     sa.Column('child_scope', String(25)),
                     sa.Column('child_name', String(255)),
                     sa.Column('scope', String(25)),
                     sa.Column('name', String(255)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('adler32', String(8)),
                     sa.Column('md5', String(32)),
                     sa.Column('guid', GUID()),
                     sa.Column('length', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column("updated_at", sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_table('archive_contents_history',
                     sa.Column('child_scope', String(25)),
                     sa.Column('child_name', String(255)),
                     sa.Column('scope', String(25)),
                     sa.Column('name', String(255)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('adler32', String(8)),
                     sa.Column('md5', String(32)),
                     sa.Column('guid', GUID()),
                     sa.Column('length', sa.BigInteger),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column("updated_at", sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('ARCH_CONTENTS_PK',
                           'archive_contents',
                           ['scope', 'name', 'child_scope', 'child_name'])
        create_primary_key('ARCH_CONT_HIST_PK',
                           'archive_contents_history',
                           ['scope', 'name', 'child_scope', 'child_name'])
        create_foreign_key('ARCH_CONTENTS_PARENT_FK', 'archive_contents', 'dids',
                           ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('ARCH_CONTENTS_CHILD_FK', 'archive_contents', 'dids',
                           ['child_scope', 'child_name'], ['scope', 'name'])

        create_index('ARCH_CONTENTS_CHILD_IDX', 'archive_contents',
                     ['child_scope', 'child_name', 'scope', 'name'])

        create_index('ARCH_CONT_HIST_IDX', 'archive_contents_history',
                     ['scope', 'name'])

        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('dids', sa.Column('is_archive',
                                     sa.Boolean(name='DIDS_ARCHIVE_CHK')), schema=schema)
        add_column('dids', sa.Column('constituent',
                                     sa.Boolean(name='DIDS_CONSTITUENT_CHK')), schema=schema)
        add_column('deleted_dids', sa.Column('is_archive', sa.Boolean()), schema=schema)
        add_column('deleted_dids', sa.Column('constituent', sa.Boolean()), schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('archive_contents')
        drop_table('archive_contents_history')

        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('dids', 'is_archive', schema=schema)
        drop_column('dids', 'constituent', schema=schema)
        drop_column('deleted_dids', 'is_archive', schema=schema)
        drop_column('deleted_dids', 'constituent', schema=schema)
