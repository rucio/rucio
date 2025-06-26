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

"""Opendata initial model"""  # noqa: D400, D415

import sqlalchemy as sa
from alembic import op

from rucio.common.schema import get_schema_value
from rucio.db.sqla.constants import OpenDataDIDState
from rucio.db.sqla.types import JSON

# Alembic revision identifiers
revision = 'a62db546a1f1'
down_revision = '30d5206e9cad'


def upgrade():
    op.create_table(
        'dids_opendata',
        sa.Column('scope', sa.String(length=get_schema_value('SCOPE_LENGTH')), nullable=False),
        sa.Column('name', sa.String(length=get_schema_value('NAME_LENGTH')), nullable=False),
        sa.Column('state', sa.Enum(OpenDataDIDState, name='DID_OPENDATA_STATE_CHK',
                                   values_callable=lambda obj: [e.value for e in obj]), nullable=True,
                  server_default=OpenDataDIDState.DRAFT.value),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('scope', 'name', name='OPENDATA_DID_PK'),
        sa.ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'],
                                ondelete='CASCADE', name='OPENDATA_DID_FK')
    )
    op.create_index('OPENDATA_DID_UPDATED_AT_IDX', 'dids_opendata', ['updated_at'])
    op.create_index('OPENDATA_DID_CREATED_AT_IDX', 'dids_opendata', ['created_at'])
    op.create_index('OPENDATA_DID_STATE_IDX', 'dids_opendata', ['state'])
    op.create_index('OPENDATA_DID_STATE_UPDATED_AT_IDX', 'dids_opendata', ['state', 'updated_at'])

    op.create_table(
        'dids_opendata_doi',
        sa.Column('scope', sa.String(length=get_schema_value('SCOPE_LENGTH')), nullable=False),
        sa.Column('name', sa.String(length=get_schema_value('NAME_LENGTH')), nullable=False),
        sa.Column('doi', sa.String(length=255), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('scope', 'name', name='OPENDATA_DOI_PK'),
        sa.ForeignKeyConstraint(['scope', 'name'], ['dids_opendata.scope', 'dids_opendata.name'],
                                ondelete='CASCADE', name='OPENDATA_DOI_FK')
    )
    op.create_index('OPENDATA_DOI_UPDATED_AT_IDX', 'dids_opendata_doi', ['updated_at'])
    op.create_index('OPENDATA_DOI_CREATED_AT_IDX', 'dids_opendata_doi', ['created_at'])

    op.create_table(
        'dids_opendata_meta',
        sa.Column('scope', sa.String(length=get_schema_value('SCOPE_LENGTH')), nullable=False),
        sa.Column('name', sa.String(length=get_schema_value('NAME_LENGTH')), nullable=False),
        sa.Column('meta', JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('scope', 'name', name='OPENDATA_META_PK'),
        sa.ForeignKeyConstraint(['scope', 'name'], ['dids_opendata.scope', 'dids_opendata.name'],
                                ondelete='CASCADE', name='OPENDATA_META_FK')
    )


def downgrade():
    op.drop_table('dids_opendata_meta')
    op.drop_table('dids_opendata_doi')
    op.drop_index('OPENDATA_DID_STATE_UPDATED_AT_IDX', table_name='dids_opendata')
    op.drop_index('OPENDATA_DID_STATE_IDX', table_name='dids_opendata')
    op.drop_index('OPENDATA_DID_CREATED_AT_IDX', table_name='dids_opendata')
    op.drop_index('OPENDATA_DID_UPDATED_AT_IDX', table_name='dids_opendata')
    op.drop_table('dids_opendata')

    # Drop enum if created in this migration
    sa.Enum(name='DID_OPENDATA_STATE_CHK').drop(op.get_bind(), checkfirst=True)
