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

""" Added vo table and vo col to rse """

import datetime

import sqlalchemy as sa
from alembic.op import bulk_insert
from sqlalchemy import String

from rucio.db.sqla.migrate_repo import (
    add_column,
    create_primary_key,
    create_table,
    create_unique_constraint,
    drop_column,
    drop_table,
    is_current_dialect,
    try_drop_constraint,
)

# Alembic revision identifiers
revision = 'a118956323f8'
down_revision = 'd1189a09c6e0'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'postgresql', 'mysql'):
        # add a vo table
        vos = create_table('vos',
                           sa.Column('vo', String(3)),
                           sa.Column('description', String(255)),
                           sa.Column('email', String(255)),
                           sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                           sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('VOS_PK', 'vos', ['vo'])

        # create base vo
        bulk_insert(vos, [{'vo': 'def',
                           'description': 'Base VO',
                           'email': 'N/A'}])

        # add a vo column
        add_column('rses', sa.Column('vo', String(3), sa.ForeignKey('vos.vo', name='RSES_VOS_FK'), nullable=False, server_default='def'))

        # change unique constraint: (rse) -> (rse,vo)
        try_drop_constraint('RSES_RSE_UQ', 'rses')
        create_unique_constraint('RSES_RSE_UQ', 'rses', ['rse', 'vo'])


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'postgresql', 'mysql'):
        # change unique constraint: (rse, vo) -> (rse)
        try_drop_constraint('RSES_RSE_UQ', 'rses')
        create_unique_constraint('RSES_RSE_UQ', 'rses', ['rse'])

        # drop vo column
        try_drop_constraint('RSES_VOS_FK', 'rses')
        drop_column('rses', 'vo')

        # drop vo table
        drop_table('vos')
