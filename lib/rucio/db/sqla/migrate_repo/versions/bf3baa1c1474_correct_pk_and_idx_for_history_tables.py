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
# Topic: Correct PK and IDX for history tables
# Revision ID: bf3baa1c1474
# Revises: 9eb936a81eb1
# Creation Date: 2019-01-28 16:25:57.818345

from alembic.op import (create_primary_key,
                        drop_constraint, create_index,
                        drop_index, drop_column, add_column)

from alembic import context

from rucio.db.sqla.types import GUID

import sqlalchemy as sa


# revision identifiers used by alembic
revision = 'bf3baa1c1474'       # pylint: disable=invalid-name
down_revision = '9eb936a81eb1'  # pylint: disable=invalid-name


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name != 'sqlite':  # pylint: disable=no-member
        # CONTENTS_HISTORY
        drop_constraint('CONTENTS_HIST_PK', 'contents_history')

        # ARCHIVE_CONTENTS_HISTORY
        drop_constraint('ARCH_CONTENTS_HISOTRY_PK', 'archive_contents_history')
        create_index('ARCH_CONT_HIST_IDX', 'archive_contents_history', ["scope", "name"])

        # RULES_HIST_RECENT
        drop_constraint('RULES_HIST_RECENT_PK', 'rules_hist_recent')
        drop_column('rules_hist_recent', 'history_id')

        # RULES_HISTORY
        drop_constraint('RULES_HIST_LONGTERM_PK', 'rules_history')
        drop_column('rules_history', 'history_id')

        # MESSAGES_HISTORY
        drop_constraint('MESSAGES_HIST_ID_PK', 'messages_history')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if context.get_context().dialect.name != 'sqlite':  # pylint: disable=no-member
        # CONTENTS_HISTORY
        create_primary_key('CONTENTS_HIST_PK', 'contents_history', ['scope', 'name', 'child_scope', 'child_name'])

        # ARCHIVE_CONTENTS_HISTORY
        create_primary_key('ARCH_CONTENTS_HISOTRY_PK', 'archive_contents_history', ['scope', 'name', 'child_scope', 'child_name'])
        drop_index('ARCH_CONT_HIST_IDX', 'archive_contents_history')

        # RULES_HIST_RECENT
        add_column('rules_hist_recent', sa.Column('history_id', GUID()))
        create_primary_key('RULES_HIST_RECENT_PK', 'rules_hist_recent', ['history_id'])

        # RULES_HISTORY
        add_column('rules_history', sa.Column('history_id', GUID()))
        create_primary_key('RULES_HIST_LONGTERM_PK', 'rules_history', ['history_id'])

        # MESSAGES_HISTORY
        create_primary_key('MESSAGES_HIST_ID_PK', 'messages_history', ['id'])
