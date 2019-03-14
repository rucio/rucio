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
# Topic: Increase size of extended_attributes column
# Revision ID: 8523998e2e76
# Revises: 3345511706b8
# Creation Date: 2019-02-15 15:45:17.171346

from alembic.op import (alter_column)

import sqlalchemy as sa


# revision identifiers used by alembic
revision = '8523998e2e76'       # pylint: disable=invalid-name
down_revision = '7ec22226cdbf'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    alter_column('rse_protocols', 'extended_attributes', existing_type=sa.String(1024), type_=sa.String(4000))


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    alter_column('rse_protocols', 'extended_attributes', existing_type=sa.String(4000), type_=sa.String(1024))
