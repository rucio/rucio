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
# Topic: New replica state for temporary unavailable replicas
# Revision ID: 7ec22226cdbf
# Revises: 3345511706b8
# Creation Date: 2019-02-14 17:47:38.995814

from alembic.op import (create_check_constraint,
                        drop_constraint)

from alembic import (context, op)


# revision identifiers used by alembic
revision = '7ec22226cdbf'       # pylint: disable=invalid-name
down_revision = '3345511706b8'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name != 'sqlite':
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be renamed first
            op.execute("ALTER TYPE 'REPLICAS_STATE_CHK' RENAME TO 'REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member
        else:
            drop_constraint('REPLICAS_STATE_CHK', 'replicas', type_='check')
        create_check_constraint(name='REPLICAS_STATE_CHK', source='replicas', condition="state in ('A', 'U', 'C', 'B', 'D', 'S', 'T')")
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be changed to the new one and the old one needs to be dropped
            op.execute("ALTER TABLE replicas ALTER COLUMN state TYPE 'REPLICAS_STATE_CHK'")  # pylint: disable=no-member
            op.execute("DROP TYPE 'REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name != 'sqlite':
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be renamed first
            op.execute("ALTER TYPE 'REPLICAS_STATE_CHK' RENAME TO 'REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member
        else:
            drop_constraint('REPLICAS_STATE_CHK', 'replicas', type_='check')
        create_check_constraint(name='REPLICAS_STATE_CHK', source='replicas', condition="state in ('A', 'U', 'C', 'B', 'D', 'S')")
        if context.get_context().dialect.name == 'postgresql':
            # For Postgres the ENUM Type needs to be changed to the new one and the old one needs to be dropped
            op.execute("ALTER TABLE replicas ALTER COLUMN state TYPE 'REPLICAS_STATE_CHK'")  # pylint: disable=no-member
            op.execute("DROP TYPE 'REPLICAS_STATE_CHK_OLD'")  # pylint: disable=no-member
