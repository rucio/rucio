# -*- coding: utf-8 -*-
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

''' Add did_type column + index on did_meta table '''

import sqlalchemy as sa
from alembic.context import get_context
from alembic.op import (add_column, drop_column,
                        create_index, drop_index,
                        execute)

from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = 'ccdbcd48206e'
down_revision = '52153819589c'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = get_context().version_table_schema + '.' if get_context().version_table_schema else ''
    if get_context().dialect.name in ['oracle', 'mysql']:
        add_column('did_meta',
                   sa.Column('did_type', sa.Enum(DIDType,
                                                 name='DID_META_DID_TYPE_CHK',
                                                 create_constraint=True,
                                                 values_callable=lambda obj: [e.value for e in obj])),
                   schema=schema[:-1])
    elif get_context().dialect.name == 'postgresql':
        execute("CREATE TYPE \"DID_META_DID_TYPE_CHK\" AS ENUM('F', 'D', 'C', 'A', 'X', 'Y', 'Z')")
        execute("ALTER TABLE %sdid_meta ADD COLUMN did_type \"DID_META_DID_TYPE_CHK\"" % schema)
    create_index('DID_META_DID_TYPE_IDX', 'did_meta', ['did_type'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    drop_index('DID_META_DID_TYPE_IDX', 'did_meta')
    schema = get_context().version_table_schema + '.' if get_context().version_table_schema else ''
    if get_context().dialect.name == 'oracle':
        try_drop_constraint('DID_META_DID_TYPE_CHK', 'did_meta')
        drop_column('did_meta', 'did_type', schema=schema[:-1])

    elif get_context().dialect.name == 'postgresql':
        execute('ALTER TABLE %sdid_meta DROP CONSTRAINT IF EXISTS "DID_META_DID_TYPE_CHK", ALTER COLUMN did_type TYPE CHAR' % schema)
        execute('ALTER TABLE %sdid_meta DROP COLUMN did_type' % schema)
        execute('DROP TYPE \"DID_META_DID_TYPE_CHK\"')

    elif get_context().dialect.name == 'mysql':
        drop_column('did_meta', 'did_type', schema=schema[:-1])
