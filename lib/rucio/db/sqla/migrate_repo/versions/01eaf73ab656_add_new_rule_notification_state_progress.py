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
# Topic: Add new rule notification state progress
# Revision ID: 01eaf73ab656
# Revises: 9eb936a81eb1
# Creation Date: 2019-01-28 10:34:46.605485

from alembic.op import (create_check_constraint, drop_constraint)

from alembic import context

# revision identifiers used by alembic
revision = '01eaf73ab656'       # pylint: disable=invalid-name
down_revision = '90f47792bb76'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name not in ('sqlite'):  # pylint: disable=no-member
        drop_constraint('RULES_NOTIFICATION_CHK', 'rules', type_='check')
        create_check_constraint(name='RULES_NOTIFICATION_CHK', source='rules',
                                condition="notification in ('Y', 'N', 'C', 'P')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name not in ('sqlite'):  # pylint: disable=no-member
        drop_constraint('RULES_NOTIFICATION_CHK', 'rules', type_='check')
        create_check_constraint(name='RULES_NOTIFICATION_CHK', source='rules',
                                condition="notification in ('Y', 'N', 'C')")
