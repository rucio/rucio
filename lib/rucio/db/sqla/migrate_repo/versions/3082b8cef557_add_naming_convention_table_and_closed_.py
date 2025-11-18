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

""" add convention table and closed_at to DIDs """

import datetime

import sqlalchemy as sa
from alembic.op import create_foreign_key, execute

from rucio.common.schema import get_schema_value
from rucio.db.sqla.constants import KeyType
from rucio.db.sqla.migrate_repo import (
    add_column,
    create_check_constraint,
    create_primary_key,
    create_table,
    drop_column,
    drop_enum_sql,
    drop_table,
    is_current_dialect,
)

# Alembic revision identifiers
revision = '3082b8cef557'
down_revision = '269fee20dee9'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('dids', sa.Column('closed_at', sa.DateTime))
        add_column('contents_history', sa.Column('deleted_at', sa.DateTime))
        create_table('naming_conventions',
                     sa.Column('scope', sa.String(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('regexp', sa.String(255)),
                     sa.Column('convention_type', sa.Enum(KeyType,
                                                          name='CVT_TYPE_CHK',
                                                          create_constraint=True,
                                                          values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('NAMING_CONVENTIONS_PK', 'naming_conventions', ['scope'])
        create_foreign_key('NAMING_CONVENTIONS_SCOPE_FK', 'naming_conventions',
                           'scopes', ['scope'], ['scope'])
        create_check_constraint('NAMING_CONVENTIONS_CREATED_NN', 'naming_conventions',
                                'created_at is not null')
        create_check_constraint('NAMING_CONVENTIONS_UPDATED_NN', 'naming_conventions',
                                'updated_at is not null')


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql'):
        drop_column('dids', 'closed_at')
        drop_column('contents_history', 'deleted_at')
        drop_table('naming_conventions')

    elif is_current_dialect('postgresql'):
        # Drop the table first to remove dependencies, then drop the enum type,
        # then remove the added columns.
        drop_table('naming_conventions')
        execute(drop_enum_sql('CVT_TYPE_CHK'))
        drop_column('dids', 'closed_at')
        drop_column('contents_history', 'deleted_at')
