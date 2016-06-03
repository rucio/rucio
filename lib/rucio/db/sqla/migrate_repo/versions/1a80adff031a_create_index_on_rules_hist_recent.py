# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015

"""Create index on rules_hist_recent

Revision ID: 1a80adff031a
Revises: ae2a56fcc89
Create Date: 2015-03-20 14:52:53.013432

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '1a80adff031a'
down_revision = '3ad36e2268b0'


def upgrade():
    op.create_index('RULES_HIST_RECENT_SC_NA_IDX', 'rules_hist_recent', ['scope', 'name'])


def downgrade():
    op.drop_index('RULES_HIST_RECENT_SC_NA_IDX', 'rules_hist_recent')
