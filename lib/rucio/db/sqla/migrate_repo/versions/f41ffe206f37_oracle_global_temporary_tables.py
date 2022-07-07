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

''' oracle_global_temporary_tables '''

import sqlalchemy as sa

from alembic import context
from alembic.op import create_table, drop_table
from rucio.common.schema import get_schema_value
from rucio.db.sqla.types import InternalScopeString, String, GUID

# Alembic revision identifiers
revision = 'f41ffe206f37'
down_revision = 'd6e2c3b2cf26'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name == 'oracle':
        additional_kwargs = {
            'oracle_on_commit': 'DELETE ROWS',
            'prefixes': ['GLOBAL TEMPORARY'],
        }
        for idx in range(5):
            create_table(
                f'TEMPORARY_SCOPE_NAME_{idx}',
                sa.Column("scope", InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
                sa.Column("name", String(get_schema_value('NAME_LENGTH'))),
                sa.PrimaryKeyConstraint('scope', 'name', name=f'TEMPORARY_SCOPE_NAME_{idx}_PK'),
                **additional_kwargs,
            )
            create_table(
                f'TEMPORARY_ASSOCIATION_{idx}',
                sa.Column("scope", InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
                sa.Column("name", String(get_schema_value('NAME_LENGTH'))),
                sa.Column("child_scope", InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
                sa.Column("child_name", String(get_schema_value('NAME_LENGTH'))),
                sa.PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name', name=f'TEMPORARY_ASSOCIATION_{idx}_PK'),
                **additional_kwargs,
            )
            create_table(
                f'TEMPORARY_ID_{idx}',
                sa.Column("id", GUID()),
                sa.PrimaryKeyConstraint('id', name=f'TEMPORARY_ID_{idx}_PK'),
                **additional_kwargs,
            )


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name == 'oracle':
        global_temp_tables = sa.inspect(context.get_bind()).get_temp_table_names()
        for idx in range(5):
            for table_name in [f'TEMPORARY_ID_{idx}', f'TEMPORARY_ASSOCIATION_{idx}', f'TEMPORARY_SCOPE_NAME_{idx}']:
                if table_name in global_temp_tables:
                    drop_table(table_name)
