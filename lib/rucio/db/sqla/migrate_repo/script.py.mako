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
# - John Doe <john.doe@asdf.com>, 2019
#
# Topic: ${message}
# Revision ID: ${up_revision}
# Revises: ${down_revision}
# Creation Date: ${create_date}

from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, rename_table)

from alembic import context

import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers used by alembic
revision = ${repr(up_revision)}       # pylint: disable=invalid-name
down_revision = ${repr(down_revision)}  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name != 'sqlite':
        ${upgrades if upgrades else "pass"}


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name != 'sqlite':
        ${downgrades if downgrades else "pass"}
