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

""" create collection_replicas_updates table """

import datetime

import sqlalchemy as sa

from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.migrate_repo import (
    add_column,
    create_check_constraint,
    create_index,
    create_primary_key,
    create_table,
    drop_column,
    drop_current_primary_key,
    drop_table,
    is_current_dialect,
    try_drop_index,
)
from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '3ad36e2268b0'
down_revision = '42db2617c364'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('collection_replicas', sa.Column('available_replicas_cnt', sa.BigInteger()))
        add_column('collection_replicas', sa.Column('available_bytes', sa.BigInteger()))

        create_table('updated_col_rep',
                     sa.Column('id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('did_type', sa.Enum(DIDType,
                                                   name='UPDATED_COL_REP_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('rse_id', GUID()),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('UPDATED_COL_REP_PK', 'updated_col_rep', ['id'])
        create_check_constraint('UPDATED_COL_REP_SCOPE_NN', 'updated_col_rep', 'scope IS NOT NULL')
        create_check_constraint('UPDATED_COL_REP_NAME_NN', 'updated_col_rep', 'name IS NOT NULL')
        create_index('UPDATED_COL_REP_SNR_IDX', 'updated_col_rep', ['scope', 'name', 'rse_id'])


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'postgresql'):
        drop_column('collection_replicas', 'available_replicas_cnt')
        drop_column('collection_replicas', 'available_bytes')
        drop_table('updated_col_rep')

    elif is_current_dialect('mysql'):
        drop_column('collection_replicas', 'available_replicas_cnt')
        drop_column('collection_replicas', 'available_bytes')
        drop_current_primary_key('updated_col_rep')
        try_drop_index('UPDATED_COL_REP_SNR_IDX', 'updated_col_rep')
        drop_table('updated_col_rep')
