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
# - Martin Barisits <martin.barisits@cern.ch>, 2019
#
# Topic: Replicas table PK definition is in wrong order
# Revision ID: 3345511706b8
# Revises: 9eb936a81eb1
# Creation Date: 2019-01-30 14:20:35.058889

from alembic.op import (create_primary_key, drop_constraint, create_foreign_key)

from alembic import context


# revision identifiers used by alembic
revision = '3345511706b8'       # pylint: disable=invalid-name
down_revision = '01eaf73ab656'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name == 'postgresql':
        # For PostgreSQL we need to drop the SOURCES_REPLICA_FK first too
        drop_constraint('SOURCES_REPLICA_FK', 'sources')
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('REPLICAS_PK', 'replicas')
        create_primary_key('REPLICAS_PK', 'replicas', ['scope', 'name', 'rse_id'])
    if context.get_context().dialect.name == 'postgresql':
        # For PostgreSQL we need to add the SOURCES_REPLICA_FK again
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name == 'postgresql':
        # For PostgreSQL we need to drop the SOURCES_REPLICA_FK first too
        drop_constraint('SOURCES_REPLICA_FK', 'sources')
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('REPLICAS_PK', 'replicas')
        create_primary_key('REPLICAS_PK', 'replicas', ['rse_id', 'scope', 'name'])
    if context.get_context().dialect.name == 'postgresql':
        # For PostgreSQL we need to add the SOURCES_REPLICA_FK again
        create_foreign_key('SOURCES_REPLICA_FK', 'sources', 'replicas', ['scope', 'name', 'rse_id'], ['scope', 'name', 'rse_id'])
