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

""" remove unique constraint on requests """

from alembic.op import create_foreign_key

from rucio.db.sqla.migrate_repo import (
    create_index,
    create_unique_constraint,
    drop_index,
    is_current_dialect,
    try_drop_constraint,
)

# Alembic revision identifiers
revision = '25821a8a45a3'
down_revision = '1803333ac20f'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        try_drop_constraint('REQUESTS_RSES_FK', 'requests')
        try_drop_constraint('REQUESTS_DID_FK', 'requests')
        try_drop_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests')
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])


def downgrade():

    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        try_drop_constraint('REQUESTS_RSES_FK', 'requests')
        try_drop_constraint('REQUESTS_DID_FK', 'requests')
        drop_index('REQUESTS_SCOPE_NAME_RSE_IDX', 'requests')
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
        create_foreign_key('REQUESTS_DID_FK', 'requests', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_unique_constraint('REQUESTS_SC_NA_RS_TY_UQ_IDX', 'requests', ['scope', 'name', 'dest_rse_id', 'request_type'])
