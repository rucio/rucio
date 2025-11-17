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

""" replicas table PK definition is in wrong order """

from alembic.op import create_foreign_key

from rucio.db.sqla.migrate_repo import (
    create_primary_key,
    drop_current_primary_key,
    is_current_dialect,
    try_drop_constraint,
    try_drop_index,
)

# revision identifiers used by alembic
revision = '3345511706b8'
down_revision = '01eaf73ab656'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'postgresql'):
        try_drop_constraint('SOURCES_REPLICA_FK', 'sources')
        drop_current_primary_key('replicas')
        create_primary_key('REPLICAS_PK', 'replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])

    elif is_current_dialect('mysql'):
        try_drop_constraint('SOURCES_REPLICA_FK', 'sources')
        # The constraint has an internal index which is not automatically dropped,
        # we have to do that manually
        try_drop_index('SOURCES_REPLICA_FK', 'sources')
        try_drop_constraint('REPLICAS_LFN_FK', 'replicas')
        try_drop_constraint('REPLICAS_RSE_ID_FK', 'replicas')
        drop_current_primary_key('replicas')
        create_foreign_key('REPLICAS_LFN_FK', 'replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('REPLICAS_RSE_ID_FK', 'replicas', 'rses', ['rse_id'], ['id'])
        create_primary_key('REPLICAS_PK', 'replicas', ['scope', 'name', 'rse_id'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'postgresql'):
        try_drop_constraint('SOURCES_REPLICA_FK', 'sources')
        drop_current_primary_key('replicas')
        create_primary_key('REPLICAS_PK', 'replicas', ['rse_id', 'scope', 'name'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['rse_id', 'scope', 'name'], ['rse_id', 'scope', 'name'])

    elif is_current_dialect('mysql'):
        try_drop_constraint('SOURCES_REPLICA_FK', 'sources')
        # The constraint has an internal index which is not automatically dropped,
        # we have to do that manually
        try_drop_index('SOURCES_REPLICA_FK', 'sources')
        try_drop_constraint('REPLICAS_LFN_FK', 'replicas')
        try_drop_constraint('REPLICAS_RSE_ID_FK', 'replicas')
        drop_current_primary_key('replicas')
        create_foreign_key('REPLICAS_LFN_FK', 'replicas', 'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('REPLICAS_RSE_ID_FK', 'replicas', 'rses', ['rse_id'], ['id'])
        create_primary_key('REPLICAS_PK', 'replicas', ['rse_id', 'scope', 'name'])
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['rse_id', 'scope', 'name'], ['rse_id', 'scope', 'name'])
