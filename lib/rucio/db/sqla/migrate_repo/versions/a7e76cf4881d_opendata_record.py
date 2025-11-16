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

"""Opendata Record ID"""  # noqa: D400, D415

import sqlalchemy as sa
from alembic.op import drop_table

from rucio.common.schema import get_schema_value
from rucio.db.sqla.migrate_repo import (
    create_index,
    create_table,
    drop_index,
)

# Alembic revision identifiers
revision = 'a7e76cf4881d'
down_revision = 'a62db546a1f1'


def upgrade():
    create_table(
        'dids_opendata_record',
        sa.Column('scope', sa.String(length=get_schema_value('SCOPE_LENGTH')), nullable=False),
        sa.Column('name', sa.String(length=get_schema_value('NAME_LENGTH')), nullable=False),
        sa.Column('record_id', sa.Integer(), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('scope', 'name', name='OPENDATA_RECORD_PK'),
        sa.ForeignKeyConstraint(['scope', 'name'], ['dids_opendata.scope', 'dids_opendata.name'],
                                ondelete='CASCADE', name='OPENDATA_RECORD_FK')
    )
    create_index('OPENDATA_RECORD_CREATED_AT_IDX', 'dids_opendata_record', ['created_at'])
    create_index('OPENDATA_RECORD_UPDATED_AT_IDX', 'dids_opendata_record', ['updated_at'])


def downgrade():
    drop_index('OPENDATA_RECORD_CREATED_AT_IDX', table_name='dids_opendata_record')
    drop_index('OPENDATA_RECORD_UPDATED_AT_IDX', table_name='dids_opendata_record')
    drop_table('dids_opendata_record')
