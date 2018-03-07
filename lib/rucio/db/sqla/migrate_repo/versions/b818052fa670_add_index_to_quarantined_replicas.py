# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Martin Barisits, <martin.barisits@cern.ch>, 2018
#
# Add index to quarantined replicas
#
# Revision ID: b818052fa670
# Revises: 2962ece31cf4
# Create Date: 2018-03-07 14:45:46.484383

from alembic.op import (create_index, drop_index)


# revision identifiers, used by Alembic.
revision = 'b818052fa670'  # pylint: disable=invalid-name
down_revision = '2962ece31cf4'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_index('QUARANTINED_REPLICAS_PATH_IDX', 'quarantined_replicas', ['path', 'rse_id'], unique=True)


def downgrade():
    '''
    downgrade method
    '''
    drop_index('QUARANTINED_REPLICAS_PATH_IDX', 'quarantined_replicas')
